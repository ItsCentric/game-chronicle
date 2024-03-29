package main

import (
	"time"

	"gorm.io/gorm"
)

type Log struct {
	gorm.Model
	Title             string    `gorm:"not null" json:"title"`
	Date              time.Time `json:"date"`
	Rating            uint      `gorm:"check:rating <= 10" gorm:"not null" json:"rating"`
	Notes             string    `json:"notes"`
	Status            LogStatus `gorm:"not null" json:"status"`
	StatusID          string    `gorm:"not null" json:"statusId"`
	Finished          bool      `json:"finished"`
	TimePlayedMinutes uint      `gorm:"not null" json:"timePlayedMinutes"`
}

type LogData struct {
	Title      string     `json:"title"`
	Date       time.Time  `json:"date"`
	Rating     uint       `json:"rating"`
	Notes      *string    `json:"notes"`
	StatusID   string     `json:"status"`
	Finished   bool       `json:"finished"`
	TimePlayed TimePlayed `json:"timePlayed"`
}

type TimePlayed struct {
	Hours   uint `json:"hours"`
	Minutes uint `json:"minutes"`
}

type LogStatus struct {
	Status string `gorm:"primaryKey"`
	Order  uint
}

func newLog(data LogData) (*Log, map[string]string) {
	logValidationError := validateCandidateLog(data)
	if len(logValidationError) > 0 {
		return nil, logValidationError
	}
	timePlayedMinutes := data.TimePlayed.Hours*60 + data.TimePlayed.Minutes

	return &Log{Title: data.Title, Date: data.Date, Rating: data.Rating, Notes: *data.Notes, StatusID: data.StatusID, Finished: data.Finished, TimePlayedMinutes: timePlayedMinutes}, nil
}

func validateCandidateLog(data LogData) map[string]string {
	validationErrors := make(map[string]string)
	if data.Title == "" {
		validationErrors["title"] = "Title cannot be empty"
	}
	if data.Date.After(time.Now()) {
		validationErrors["date"] = "Date cannot be in the future"
	}
	if data.Rating > 10 || data.Rating < 0 {
		validationErrors["rating"] = "Rating must be between 0 and 10"
	}
	if data.TimePlayed.Hours < 0 || data.TimePlayed.Minutes < 0 {
		validationErrors["timePlayed"] = "Time played cannot be negative"
	}
	if data.TimePlayed.Minutes > 59 {
		validationErrors["timePlayed"] = "Minutes cannot be greater than 59"
	}
	if data.StatusID == "" {
		validationErrors["status"] = "Status cannot be empty"
	}

	return validationErrors
}
