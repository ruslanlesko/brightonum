package dao

import (
	"context"
	"os"
	"os/signal"
	s "ruslanlesko/brightonum/src/structs"
	"strings"
	"syscall"

	"github.com/go-pkgz/lgr"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var loggerFormat = lgr.Format(`{{.Level}} {{.DT.Format "2006-01-02 15:04:05.000"}} {{.Message}}`)
var logger = lgr.New(loggerFormat)

const collectionName string = "users"

// MongoUserDao provides UserDao implementation via MongoDB
type MongoUserDao struct {
	Client       *mongo.Client
	DatabaseName string
	Ctx          context.Context
}

// MaxIDResponse for response on pipe. Used for extracting current max id
type MaxIDResponse struct {
	_ID   string `bson:"_id"`
	MaxID int    `bson:"MaxID"`
}

// NewMongoUserDao creates instance of MongoUserDao
func NewMongoUserDao(URL string, databaseName string) *MongoUserDao {
	ctx, cancel := context.WithCancel(context.Background())
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(URL))

	if err != nil {
		logger.Logf("ERROR Failed to dial mongo url: '%s'", URL)
		panic(err)
	}
	logger.Logf("INFO Connected to MongoDB")

	sigChan := make(chan os.Signal)
	go func() {
		for range sigChan {
			logger.Logf("INFO disconnecting from MongoDB")
			client.Disconnect(ctx)
			logger.Logf("INFO disconnected from MongoDB")
			cancel()
		}
	}()
	signal.Notify(sigChan, syscall.SIGTERM)

	return &MongoUserDao{Client: client, DatabaseName: databaseName, Ctx: ctx}
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

	collection := d.Client.Database(d.DatabaseName).Collection(collectionName)

	newID := findNextID(d.Ctx, collection)

	if newID < 0 {
		return -1
	}
	u.ID = newID

	_, err := collection.InsertOne(d.Ctx, &u)
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

func findNextID(ctx context.Context, collection *mongo.Collection) int {
	resp := &MaxIDResponse{}

	cur, err := collection.Aggregate(ctx, []bson.M{
		{"$group": bson.M{
			"_id":   nil,
			"MaxID": bson.M{"$max": "$_id"},
		},
		},
	})
	defer cur.Close(ctx)

	if err != nil {
		logger.Logf("ERROR %s", err.Error())
		return -1
	}

	if cur.Next(ctx) {
		cur.Decode(resp)
		return resp.MaxID + 1
	}

	return 1
}

// GetByUsername extracts user by username
func (d *MongoUserDao) GetByUsername(username string) (*s.User, error) {
	result := &s.User{}

	collection := d.Client.Database(d.DatabaseName).Collection(collectionName)
	err := collection.FindOne(d.Ctx, bson.M{
		"username": strings.ToLower(username),
	}).Decode(result)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		logger.Logf("ERROR %s", err)
		return nil, err
	}

	return result, nil
}

// GetByEmail returns nil when user is not found
// Returns error if data access error occured
func (d *MongoUserDao) GetByEmail(email string) (*s.User, error) {
	result := &s.User{}

	collection := d.Client.Database(d.DatabaseName).Collection(collectionName)
	err := collection.FindOne(d.Ctx, bson.M{
		"email": strings.ToLower(email),
	}).Decode(result)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		logger.Logf("ERROR %s", err)
		return nil, err
	}

	return result, nil
}

// Get returns user by id
func (d *MongoUserDao) Get(id int) (*s.User, error) {
	result := &s.User{}

	collection := d.Client.Database(d.DatabaseName).Collection(collectionName)

	err := collection.FindOne(d.Ctx, bson.M{
		"_id": id,
	}).Decode(result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		logger.Logf("ERROR %s", err)
		return nil, err
	}

	return result, nil
}

// GetAll extracts all users
func (d *MongoUserDao) GetAll() (*[]s.User, error) {
	result := []s.User{}

	collection := d.Client.Database(d.DatabaseName).Collection(collectionName)
	cur, err := collection.Find(d.Ctx, bson.M{})
	if err != nil {
		logger.Logf("ERROR %s", err)
		return nil, err
	}
	defer cur.Close(d.Ctx)
	for cur.Next(d.Ctx) {
		u := s.User{}
		err = cur.Decode(&u)
		if err != nil {
			logger.Logf("ERROR %s", err)
			return nil, err
		}
		result = append(result, u)
	}

	return &result, nil
}

// Update updates user if exists
func (d *MongoUserDao) Update(u *s.User) error {
	collection := d.Client.Database(d.DatabaseName).Collection(collectionName)

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

	_, err := collection.UpdateOne(d.Ctx, bson.M{"_id": u.ID}, bson.M{"$set": updateBody})
	return err
}

// SetRecoveryCode sets password recovery code for user id
func (d *MongoUserDao) SetRecoveryCode(id int, code string) error {
	return d.setFieldAndWipeOtherForId(id, "recoveryCode", code, "resettingCode")
}

// GetRecoveryCode extracts recovery code for user id
func (d *MongoUserDao) GetRecoveryCode(id int) (string, error) {
	return d.getStringFieldForId(id, "recoveryCode")
}

// SetResettingCode sets resetting code and removes recovery one
func (d *MongoUserDao) SetResettingCode(id int, code string) error {
	return d.setFieldAndWipeOtherForId(id, "resettingCode", code, "recoveryCode")
}

// GetResettingCode extracts resetting code for user id
func (d *MongoUserDao) GetResettingCode(id int) (string, error) {
	return d.getStringFieldForId(id, "resettingCode")
}

// ResetPassword updates password and removes resetting code
func (d *MongoUserDao) ResetPassword(id int, passwordHash string) error {
	return d.setFieldAndWipeOtherForId(id, "password", passwordHash, "resettingCode")
}

// DeleteById deletes user by id
func (d *MongoUserDao) DeleteById(id int) error {
	collection := d.Client.Database(d.DatabaseName).Collection(collectionName)
	_, err := collection.DeleteOne(d.Ctx, bson.M{"_id": id})
	return err
}

func (d *MongoUserDao) getStringFieldForId(id int, field string) (string, error) {
	collection := d.Client.Database(d.DatabaseName).Collection(collectionName)

	var result bson.M

	opt := options.FindOne().SetProjection(bson.M{"_id": 0, field: 1})
	err := collection.FindOne(d.Ctx, bson.M{"_id": id}, opt).Decode(&result)

	if err != nil {
		return "", err
	}

	return result[field].(string), nil
}

func (d *MongoUserDao) setFieldAndWipeOtherForId(id int, fieldToSet string, value string, fieldToWipe string) error {
	collection := d.Client.Database(d.DatabaseName).Collection(collectionName)

	updateBody := bson.M{fieldToSet: value, fieldToWipe: ""}

	_, err := collection.UpdateOne(d.Ctx, bson.M{"_id": id}, bson.M{"$set": updateBody})
	return err
}
