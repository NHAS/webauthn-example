package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/go-webauthn/webauthn/webauthn"
)

type sessiondb struct {
	sessions map[string]*webauthn.SessionData
	mu       sync.RWMutex
}

var sessionDb *sessiondb = &sessiondb{
	sessions: make(map[string]*webauthn.SessionData),
}

// GetUser returns a *User by the user's username
func (db *sessiondb) GetSession(sessionID string) (*webauthn.SessionData, error) {

	db.mu.Lock()
	defer db.mu.Unlock()

	session, ok := db.sessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("error getting session '%s': does not exist", sessionID)
	}

	return session, nil
}

func (db *sessiondb) DeleteSession(sessionID string) {
	db.mu.Lock()
	defer db.mu.Unlock()

	delete(db.sessions, sessionID)
}

// PutUser stores a new user by the user's username
func (db *sessiondb) StartSession(data *webauthn.SessionData) string {

	db.mu.Lock()
	defer db.mu.Unlock()

	sessionId, _ := random(32)
	db.sessions[sessionId] = data

	return sessionId
}

func random(length int) (string, error) {
	randomData := make([]byte, length)
	_, err := rand.Read(randomData)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(randomData), nil
}
