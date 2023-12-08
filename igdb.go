package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
)

type AccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

type SimplifiedIgdbCover struct {
	Id       int     `json:"id"`
	Image_id *string `json:"image_id"`
}

type IgdbGame struct {
	Name  string              `json:"name"`
	Cover SimplifiedIgdbCover `json:"cover"`
}

func (a *App) AuthenticateWithTwitch() (AccessTokenResponse, error) {
	twitchClientId := os.Getenv("TWITCH_CLIENT_ID")
	if twitchClientId == "" {
		return AccessTokenResponse{}, errors.New("twitchClientId environment variable not set")
	}
	twitchClientSecret := os.Getenv("TWITCH_CLIENT_SECRET")
	if twitchClientSecret == "" {
		return AccessTokenResponse{}, errors.New("twitchClientSecret environment variable not set")
	}
	requestUrl := fmt.Sprintf("https://id.twitch.tv/oauth2/token?client_id=%s&client_secret=%s&grant_type=client_credentials", twitchClientId, twitchClientSecret)
	accessTokenResponse, err := http.Post(requestUrl, "application/json", nil)
	if err != nil {
		return AccessTokenResponse{}, err
	}
	defer accessTokenResponse.Body.Close()
	accessTokenResponseBody, err := io.ReadAll(accessTokenResponse.Body)
	if err != nil {
		return AccessTokenResponse{}, err
	}
	var accessToken AccessTokenResponse
	err = json.Unmarshal(accessTokenResponseBody, &accessToken)
	if err != nil {
		return AccessTokenResponse{}, err
	}

	return accessToken, nil
}

func SendIgdbRequest(endpoint string, accessToken string, body string) ([]byte, error) {
	request, err := http.NewRequest(http.MethodPost, fmt.Sprintf("https://api.igdb.com/v4/%s", endpoint), bytes.NewBuffer([]byte(body)))
	if err != nil {
		return []byte{}, err
	}
	request.Header.Set("Client-ID", os.Getenv("TWITCH_CLIENT_ID"))
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return []byte{}, err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return []byte{}, err
	}

	return responseBody, nil
}

func (a *App) SearchForGame(title string, accessToken string) ([]IgdbGame, error) {
	responseBody, err := SendIgdbRequest("games", accessToken, fmt.Sprintf("search \"%s\"; fields name, cover.image_id; limit 3; where category = 0;", title))
	if err != nil {
		return []IgdbGame{}, err
	}
	var igdbGames []IgdbGame
	err = json.Unmarshal(responseBody, &igdbGames)
	if err != nil {
		return []IgdbGame{}, err
	}

	return igdbGames, nil
}
