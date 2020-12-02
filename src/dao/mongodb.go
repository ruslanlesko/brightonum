package dao

import (
	"os"
	"os/signal"
	s "ruslanlesko/brightonum/src/structs"
	"strings"
	"syscall"

	"github.com/go-pkgz/lgr"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

var loggerFormat = lgr.Format(`{{.Level}} {{.DT.Format "2006-01-02 15:04:05.000"}} {{.Message}}`)
var logger = lgr.New(loggerFormat)

const collectionName string = "users"

// MongoUserDao provides UserDao implementation via MongoDB
type MongoUserDao struct {
	Session      *mgo.Session
	DatabaseName string
}

// MaxIDResponse for response on pipe. Used for extracting current max id
type MaxIDResponse struct {
	_ID   string `bson:"_id"`
	MaxID int    `bson:"MaxID"`
}

func NewMongoUserDao(URL string, databaseName string) *MongoUserDao {
	session, err := mgo.Dial(URL)
	if err != nil {
		logger.Logf("ERROR Failed to dial mongo url: '%s'", URL)
		panic(err)
	}
	logger.Logf("INFO Connected to MongoDB")

	sigChan := make(chan os.Signal)
	go func() {
		for range sigChan {
			logger.Logf("INFO disconnecting from MongoDB")
			session.Close()
			logger.Logf("INFO disconnected from MongoDB")
		}
	}()
	signal.Notify(sigChan, syscall.SIGTERM)

	return &MongoUserDao{Session: session, DatabaseName: databaseName}
}

// Save saves user in MongoDB.
// Implemented to retry insertion several times if another thread inserts document between
// calculation of new id and insertion into collection.
func (d *MongoUserDao) Save(u *s.User) int {
	u.Username = strings.ToLower(u.Username)
	return d.doSave(u, 5)
}

func (d *MongoUserDao) doSave(u *s.User, attemptsLeft int) int {
	if attemptsLeft == 0 {
		return -1
	}

	session := d.Session.Clone()
	defer session.Close()

	newID := findNextID(session, d.DatabaseName)

	if newID < 0 {
		return -1
	}
	u.ID = newID

	collection := session.DB(d.DatabaseName).C(collectionName)
	err := collection.Insert(&u)
	if err != nil {
		logger.Logf("ERROR %s", err)

		// Retry if another document was inserted at this moment
		if strings.Contains(err.Error(), "duplicate") {
			return d.doSave(u, attemptsLeft-1)
		}
		return -1
	}

	return newID
}

func findNextID(session *mgo.Session, databaseName string) int {
	resp := []MaxIDResponse{}

	collection := session.DB(databaseName).C(collectionName)
	err := collection.Pipe([]bson.M{
		{"$group": bson.M{
			"_id":   nil,
			"MaxID": bson.M{"$max": "$_id"},
		},
		},
	}).All(&resp)
	if err != nil {
		logger.Logf("ERROR %s", err.Error())
		return -1
	}

	if len(resp) == 0 {
		return 1
	}

	return resp[0].MaxID + 1
}

// GetByUsername extracts user by username
func (d *MongoUserDao) GetByUsername(username string) (*s.User, error) {
	result := []s.User{}

	session := d.Session.Clone()
	defer session.Close()

	collection := session.DB(d.DatabaseName).C(collectionName)
	err := collection.Find(bson.M{
		"username": strings.ToLower(username),
	}).All(&result)
	if err != nil {
		logger.Logf("ERROR %s", err)
		return nil, err
	}

	if len(result) == 0 {
		return nil, nil
	}

	return &result[0], nil
}

// Get returns user by id
func (d *MongoUserDao) Get(id int) (*s.User, error) {
	result := []s.User{}

	session := d.Session.Clone()
	defer session.Close()

	collection := session.DB(d.DatabaseName).C(collectionName)
	err := collection.Find(bson.M{
		"_id": id,
	}).All(&result)
	if err != nil {
		logger.Logf("ERROR %s", err)
		return nil, err
	}

	if len(result) == 0 {
		return nil, nil
	}

	return &result[0], nil
}

func (d *MongoUserDao) GetAll() (*[]s.User, error) {
	result := []s.User{}

	session := d.Session.Clone()
	defer session.Close()

	collection := session.DB(d.DatabaseName).C(collectionName)
	err := collection.Find(bson.M{}).All(&result)
	if err != nil {
		logger.Logf("ERROR %s", err)
		return nil, err
	}

	return &result, nil
}

// Update updates user if exists
func (d *MongoUserDao) Update(u *s.User) error {
	session := d.Session.Clone()
	defer session.Close()

	collection := session.DB(d.DatabaseName).C(collectionName)

	updateBody := bson.M{}
	if u.FirstName != "" {
		updateBody["firstName"] = u.FirstName
	}
	if u.LastName != "" {
		updateBody["lastName"] = u.LastName
	}
	if u.Email != "" {
		updateBody["email"] = u.Email
	}
	if u.Password != "" {
		updateBody["password"] = u.Password
	}

	return collection.UpdateId(u.ID, bson.M{"$set": updateBody})
}
