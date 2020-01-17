package main

import (
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

// UserDao provides interface to persisting operations
type UserDao interface {
	Save(*User) int
	GetByUsername(string) *User
}

// MemoryUserDao implementation for UserDao
type MemoryUserDao struct {
	Users map[int]*User
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

// MongoUserDao provides UserDao implementation via MongoDB
type MongoUserDao struct {
	URL	string
	databaseName string
}

// MaxIDResponse for response on pipe
type MaxIDResponse struct {
	_ID		string	`bson:"_id"`
	MaxID	int		`bson:"MaxID"`
}

// Save saves user in MongoDB
func (d *MongoUserDao) Save(u *User) int {
	session, err := mgo.Dial(d.URL)
	if err != nil {
		panic(err)
	}
	defer session.Close()

	result := []MaxIDResponse{}

	collection := session.DB(d.databaseName).C("users")
	err = collection.Pipe([]bson.M{
		{"$group": 
			bson.M{
				"_id": nil, 
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
	session, err := mgo.Dial(d.URL)
	if err != nil {
		panic(err)
	}
	defer session.Close()

	result := []User{}

	collection := session.DB(d.databaseName).C("users")
	err = collection.Find(bson.M{
		"username": username,
	}).All(&result)

	if len(result) == 0 {
		return nil
	}

	return &result[0]
}