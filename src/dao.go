package main

import (
	"os"
	"os/signal"
	"syscall"

	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

// UserDao provides interface to persisting operations
type UserDao interface {
	Save(*User) int
	GetByUsername(string) *User
	Get(int) *User
}

// MemoryUserDao implementation for UserDao
type MemoryUserDao struct {
	Users    map[int]*User
	LatestID int
}

// Save saves user
func (d *MemoryUserDao) Save(u *User) int {
	newID := d.LatestID + 1
	d.LatestID = newID
	d.Users[newID] = u
	return newID
}

// GetByUsername returns user by username
func (d *MemoryUserDao) GetByUsername(username string) *User {
	for _, u := range d.Users {
		if u.Username == username {
			return u
		}
	}
	return nil
}

// Get returns user by id
func (d *MemoryUserDao) Get(id int) *User {
	return d.Users[id]
}

// MongoUserDao provides UserDao implementation via MongoDB
type MongoUserDao struct {
	Session      *mgo.Session
	databaseName string
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

	return &MongoUserDao{Session: session, databaseName: databaseName}
}

// MaxIDResponse for response on pipe
type MaxIDResponse struct {
	_ID   string `bson:"_id"`
	MaxID int    `bson:"MaxID"`
}

// Save saves user in MongoDB
func (d *MongoUserDao) Save(u *User) int {
	result := []MaxIDResponse{}

	collection := d.Session.DB(d.databaseName).C("users")
	err := collection.Pipe([]bson.M{
		{"$group": bson.M{
			"_id":   nil,
			"MaxID": bson.M{"$max": "$id"},
		},
		},
	}).All(&result)
	if err != nil {
		panic(err)
	}

	newID := 1
	if len(result) > 0 {
		newID = result[0].MaxID + 1
	}

	u.ID = newID

	collection.Insert(&u)

	return newID
}

// GetByUsername extracts user by username
func (d *MongoUserDao) GetByUsername(username string) *User {
	result := []User{}

	collection := d.Session.DB(d.databaseName).C("users")
	err := collection.Find(bson.M{
		"username": username,
	}).All(&result)
	if err != nil {
		panic(err)
	}

	if len(result) == 0 {
		return nil
	}

	return &result[0]
}

// Get returns user by id
func (d *MongoUserDao) Get(id int) *User {
	result := []User{}

	collection := d.Session.DB(d.databaseName).C("users")
	err := collection.Find(bson.M{
		"id": id,
	}).All(&result)
	if err != nil {
		panic(err)
	}

	if len(result) == 0 {
		return nil
	}

	return &result[0]
}
