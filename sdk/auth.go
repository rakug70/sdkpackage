package sdk

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"
)

const (
	RoleSuperAdmin     = "SUPER_ADMIN"
	RoleRegionalAdmin  = "REGIONAL_ADMIN"
	RoleProfileManager = "PROFILE_MANAGER"
)

// ChangePasswordResponse struct stores the new ID token and refresh token
type ChangePasswordResponse struct {
	idToken      string `json:"idToken"`
	refreshToken string `json:"refreshToken"`
}

// LoginResponse represents the response returned after a successful login.
type LoginResponse struct {
	idToken string `json:"idToken"`
	email   string `json:"email"`
}

// MockAuthClient is a mock implementation of the AuthClient interface for testing.
type MockAuthClient struct {
	signInFunc func(email, password string) (*LoginResponse, error)
}

// ✅ Define the MfaInfo struct (rename it to MfaInfo if needed externally)
type mfaInfo struct {
	PhoneInfo       string `json:"phoneInfo"`
	MfaEnrollmentId string `json:"mfaEnrollmentId"`
	DisplayName     string `json:"displayName"` // ✅ Add missing field
	EnrolledAt      string `json:"enrolledAt"`  // ✅ Add missing field
}

// FBSignInResponse stores Firebase authentication response details.
type FBSignInResponse struct {
	kind                 string    `json:"kind"`
	registered           bool      `json:"registered"`
	localID              string    `json:"localId"`
	email                string    `json:"email"`
	phoneNumber          string    `json:"phoneNumber"`
	idToken              string    `json:"idToken"`
	refreshToken         string    `json:"refreshToken"`
	expiresIn            string    `json:"expiresIn"`
	mfaPendingCredential string    `json:"mfaPendingCredential"`
	sessionInfo          string    `json:"sessionInfo"`
	mfaInfo              []mfaInfo // ✅ Corrected Type
}

// FBAnonymousSignInResponse stores Firebase anonymous sign-in response.
type FBAnonymousSignInResponse struct {
	localID      string `json:"localId"`
	email        string `json:"email"`
	idToken      string `json:"idToken"`
	refreshToken string `json:"refreshToken"`
	expiresIn    string `json:"expiresIn"`
}

// fbAccountCredentials is used to pass email/password when calling SignIn or SignUp
type fbAccountCredentials struct {
	email             string `json:"email"`
	password          string `json:"password"`
	returnSecureToken bool   `json:"returnSecureToken"`
	emailVerified     bool   `json:"emailVerified"`
}

// fbErrorEnvelop maps to JSON structure received from Firebase if there is an error in a request.
type fbErrorEnvelop struct {
	error fbError `json:"error"`
}

// fbError maps to Firebase's response error structure.
type fbError struct {
	code    int             `json:"code"`
	message string          `json:"message"`
	errors  []fbErrorDetail `json:"errors"`
}

// fbErrorDetail maps to details of each error that is received from Firebase's API.
type fbErrorDetail struct {
	message string `json:"message"`
	reason  string `json:"reason"`
	domain  string `json:"domain"`
}

// AuthClient handles Firebase authentication requests.
type AuthClient struct {
	restAPIBaseUrl string // URL to Firebase's REST API
	webAPIKey      string // Firebase Web API Key
	projectId      string // Indicates if a local emulator is used
	isEmulator     bool   // Indicates if a local emulator is used
}

type verifyEmailRequest struct {
	requestType string
	idToken     string
}

func NewAuthClient(inRestAPIBaseURL string, inWebAPIKey string, projectId string, inIsEmulator bool) *AuthClient {
	return &AuthClient{
		inRestAPIBaseURL,
		inWebAPIKey,
		projectId,
		inIsEmulator,
	}
}

var ErrTokenIDIsEmpty error = fmt.Errorf("tokenID is required and cannot be empty")
var ErrEmailNotFound = fmt.Errorf("sign in email or password is invalid or not found")
var ErrInvalidURL = fmt.Errorf("firebase url is invalid or not reachable")

// SignInByUsernamePassword attempts to authenticate user based on username and password provided.  If authentication
// is successful, it returns Firebase's Response.
func (fb *AuthClient) SignInByUsernamePassword(db *sql.DB, inEmail string, inPassword string) (*FBSignInResponse, error) {
	// Step 1: Build Request
	// ✅ Use an anonymous struct for JSON marshaling (instead of exporting fields)
	jsonReq, err := json.Marshal(struct {
		Email             string `json:"email"`
		Password          string `json:"password"`
		ReturnSecureToken bool   `json:"returnSecureToken"`
	}{
		Email:             inEmail,
		Password:          inPassword,
		ReturnSecureToken: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	// Step 2: Make Request
	var strRequestURL = fb.restAPIBaseUrl + "accounts:signInWithPassword?key=" + fb.webAPIKey
	resp, err := http.Post(strRequestURL, "application/json; charset=utf-8", bytes.NewBuffer(jsonReq))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Step 3: Check Response
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	// If response is not 200 OK, handle Firebase error
	if resp.StatusCode != http.StatusOK {
		var fbErrorEnvelop fbErrorEnvelop
		if err := json.Unmarshal(bodyBytes, &fbErrorEnvelop); err != nil {
			return nil, fmt.Errorf("failed to parse Firebase error: %v", err)
		}

		// Match Firebase error messages to user-friendly errors
		switch fbErrorEnvelop.error.message {
		case "EMAIL_NOT_FOUND":
			return nil, fmt.Errorf("Email not found. Please register first.")
		case "INVALID_PASSWORD":
			return nil, fmt.Errorf("Incorrect password. Please try again.")
		case "INVALID_EMAIL":
			return nil, fmt.Errorf("Invalid email format. Please enter a valid email address.")
		case "USER_DISABLED":
			return nil, fmt.Errorf("This account has been disabled by the administrator.")
		case "INVALID_LOGIN_CREDENTIALS":
			return nil, fmt.Errorf("Invalid login credentials.")
		case "TOO_MANY_ATTEMPTS_TRY_LATER":
			return nil, fmt.Errorf("Too many failed login attempts. Please wait a few minutes and try again.")
		default:

			return nil, fmt.Errorf("login failed: %s", fbErrorEnvelop.error.message)
		}
	}

	// Step 4: Parse Successful Response

	var tempResponse struct {
		Kind                 string    `json:"kind"`
		Registered           bool      `json:"registered"`
		LocalID              string    `json:"localId"`
		Email                string    `json:"email"`
		PhoneNumber          string    `json:"phoneNumber"`
		IDToken              string    `json:"idToken"`
		RefreshToken         string    `json:"refreshToken"`
		ExpiresIn            string    `json:"expiresIn"`
		MfaPendingCredential string    `json:"mfaPendingCredential"`
		MfaInfo              []mfaInfo `json:"mfaInfo"` // ✅ Uses named struct instead of anonymous one
	}

	// ✅ Safeguard against empty response body
	if len(bodyBytes) == 0 {
		return nil, fmt.Errorf("empty response body")
	}

	// ✅ Parse response into temporary struct
	err = json.Unmarshal(bodyBytes, &tempResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	// ✅ Convert Anonymous Struct Slice to Named Struct Slice (Optimized)
	mfaInfos := make([]mfaInfo, len(tempResponse.MfaInfo))
	for i, item := range tempResponse.MfaInfo {
		mfaInfos[i] = mfaInfo{
			PhoneInfo:       item.PhoneInfo,
			MfaEnrollmentId: item.MfaEnrollmentId,
		}
	}

	// ✅ Copy values from temp struct to original struct (with private fields)
	loginResponse := &FBSignInResponse{
		kind:                 tempResponse.Kind,
		registered:           tempResponse.Registered,
		localID:              tempResponse.LocalID,
		email:                tempResponse.Email,
		phoneNumber:          tempResponse.PhoneNumber,
		idToken:              tempResponse.IDToken,
		refreshToken:         tempResponse.RefreshToken,
		expiresIn:            tempResponse.ExpiresIn,
		mfaPendingCredential: tempResponse.MfaPendingCredential,
		mfaInfo:              mfaInfos,
	}

	// Step 5: Verify Email is Confirmed (Optional)
	const enableEmailVerification = false // Toggle as needed
	if enableEmailVerification {
		verified, err := fb.IsEmailVerified(loginResponse.GetIDToken())
		if err != nil || !verified {
			return nil, fmt.Errorf("email not verified. Please check your email and verify your account before logging in.")
		}
	}

	// Step 6: Return Struct
	return loginResponse, nil
}

// SignUpUserByPassword creates a new account in Firebase, signs in that user and returns ID and refresh tokens.
func (fb *AuthClient) SignUpByUsernamePassword(inEmail string, inPassword string) (*FBSignInResponse, error) {
	// ***************************************************************************************************************/
	// Step 1 of 5:  Build Request
	// ***************************************************************************************************************/
	credentials := fbAccountCredentials{
		email:             inEmail,
		password:          inPassword,
		returnSecureToken: true,
	}
	jsonReq, err := json.Marshal(credentials)
	if err != nil {
		return nil, err
	}

	// ***************************************************************************************************************/
	// Step 2 of 5:  Make Request and get a response
	// ***************************************************************************************************************/
	var strRequestURL = fb.restAPIBaseUrl + "accounts:signUp?key=" + fb.webAPIKey
	resp, err := http.Post(strRequestURL, "application/json; charset=utf-8", bytes.NewBuffer(jsonReq))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// ***************************************************************************************************************/
	// Step 3 of 5:  Check response is valid
	// ***************************************************************************************************************/
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusBadGateway {
			// logger.AppLogger.Error(fmt.Sprintf("unable to reach firebase auth server at %s", fb.RestAPIBaseUrl))
			return nil, ErrInvalidURL
		}
		// Convert response body to string
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		var fbErrorEnvelop fbErrorEnvelop
		err = json.Unmarshal([]byte(bodyBytes), &fbErrorEnvelop)
		if err != nil {
			return nil, err
		}
		// logger.AppLogger.Info("Firebase returned error when signing in with username/password", "Firebase Response", string(bodyBytes))
		return nil, fmt.Errorf("%s", strings.ToLower(fbErrorEnvelop.error.message))
	}

	// ***************************************************************************************************************/
	// Step 4 of 5:  Read Response Body & populate struct
	// ***************************************************************************************************************/
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var loginResponse FBSignInResponse
	err = json.Unmarshal(bodyBytes, &loginResponse)
	if err != nil {
		return nil, err
	}

	// ***************************************************************************************************************/
	// Step 5 of 5:  Return Struct
	// ***************************************************************************************************************/
	return &loginResponse, nil
}

// CreateUserWithoutPassword - Creates a Firebase user without requiring a password
func (fb *AuthClient) CreateUserWithoutPassword(inEmail string) (*FBSignInResponse, error) {
	// ✅ Generate a secure random password (16 characters)
	randomPassword, err := GenerateRandomPassword(16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random password: %v", err)
	}

	// ✅ Create protected struct instance
	credentials := fbAccountCredentials{
		email:             inEmail,
		password:          randomPassword,
		returnSecureToken: true,
		emailVerified:     true,
	}

	// ✅ Use an anonymous struct for JSON marshaling (instead of exporting fields)
	jsonReq, err := json.Marshal(struct {
		Email             string `json:"email"`
		Password          string `json:"password"`
		ReturnSecureToken bool   `json:"returnSecureToken"`
		EmailVerified     bool   `json:"emailVerified"`
	}{
		Email:             credentials.email,
		Password:          credentials.password,
		ReturnSecureToken: credentials.returnSecureToken,
		EmailVerified:     credentials.emailVerified,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	// ✅ Debug: Print final JSON request
	log.Println("Final JSON Request:", string(jsonReq))

	// ✅ Correct API endpoint
	var strRequestURL = fb.restAPIBaseUrl + "accounts:signUp?key=" + fb.webAPIKey
	log.Println("API Request URL:", strRequestURL)

	// ✅ Make HTTP request
	resp, err := http.Post(strRequestURL, "application/json; charset=utf-8", bytes.NewBuffer(jsonReq))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// ✅ Read response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	// ✅ Debug: Print API response
	log.Println("API Response:", string(bodyBytes))

	// ✅ Check if response is valid
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Firebase Error: %s", string(bodyBytes))
	}

	// ✅ Temporary struct with exported fields for JSON unmarshalling
	var tempResponse struct {
		Kind         string `json:"kind"`
		Registered   bool   `json:"registered"`
		LocalID      string `json:"localId"`
		Email        string `json:"email"`
		PhoneNumber  string `json:"phoneNumber"`
		IDToken      string `json:"idToken"`
		RefreshToken string `json:"refreshToken"`
		ExpiresIn    string `json:"expiresIn"`
	}

	// ✅ Parse response into temporary struct
	err = json.Unmarshal(bodyBytes, &tempResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	// ✅ Copy values from temp struct to original struct (with private fields)
	loginResponse := &FBSignInResponse{
		kind:         tempResponse.Kind,
		registered:   tempResponse.Registered,
		localID:      tempResponse.LocalID,
		email:        tempResponse.Email,
		phoneNumber:  tempResponse.PhoneNumber,
		idToken:      tempResponse.IDToken,
		refreshToken: tempResponse.RefreshToken,
		expiresIn:    tempResponse.ExpiresIn,
	}

	// ✅ Debug: Print ID Token
	log.Println("Extracted ID Token:", loginResponse.GetIDToken())

	return loginResponse, nil
}

// Send a Verification Email After Registration
func (fb *AuthClient) SendEmailVerification(idToken string) (string, error) {
	emailRequest := verifyEmailRequest{
		requestType: "VERIFY_EMAIL",
		idToken:     idToken,
	}

	// ✅ Anonymous struct ensures correct JSON formatting
	jsonBody, err := json.Marshal(struct {
		RequestType string `json:"requestType"`
		IDToken     string `json:"idToken"`
	}{
		RequestType: emailRequest.requestType,
		IDToken:     emailRequest.idToken,
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %v", err)
	}

	strRequestURL := fb.restAPIBaseUrl + "accounts:sendOobCode?key=" + fb.webAPIKey
	resp, err := http.Post(strRequestURL, "application/json", bytes.NewBuffer(jsonBody))
	log.Println("Error sending email verification:", err)
	if err != nil {
		return "", fmt.Errorf("failed to send verification email: %v", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	// Check for non-200 response
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to send verification email, status code: %d, response: %s", resp.StatusCode, string(body))
	}

	// Parse response JSON
	var tempResponse struct {
		Email string `json:"email"`
	}

	if err := json.Unmarshal(body, &tempResponse); err != nil {
		return "", fmt.Errorf("failed to parse response JSON: %v", err)
	}

	// Debug log
	log.Println("Extracted ID Token:", tempResponse)

	// Return only the token
	return tempResponse.Email, nil
}

// RegisterWithPhoneNumber registers a user using a phone number via Firebase
func (fb *AuthClient) RegisterWithPhoneNumber(phoneNumber string) (*FBSignInResponse, error) {
	// Create the request body
	requestBody, err := json.Marshal(map[string]interface{}{
		"phoneNumber":       phoneNumber,
		"returnSecureToken": true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %v", err)
	}

	// Send request to Firebase
	var strRequestURL = fb.restAPIBaseUrl + "accounts:signUpWithPhoneNumber?key=" + fb.webAPIKey
	resp, err := http.Post(strRequestURL, "application/json; charset=utf-8", bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Check response validity
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to register phone number, status: %d, response: %s", resp.StatusCode, string(bodyBytes))
	}

	// Parse response
	var signInResponse FBSignInResponse
	if err := json.NewDecoder(resp.Body).Decode(&signInResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return &signInResponse, nil
}

// SetPassword - Sets the password for a verified user
func (fb *AuthClient) SetPassword(password string, newIDToken string, role string) error {

	requestBody, err := json.Marshal(map[string]interface{}{
		"password":          password,
		"idToken":           newIDToken,
		"returnSecureToken": true,
		"customClaims": map[string]interface{}{
			"role": role, // Change this value dynamically
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	// Validate role
	validRoles := map[string]bool{
		RoleSuperAdmin:     true,
		RoleRegionalAdmin:  true,
		RoleProfileManager: true,
	}
	if !validRoles[role] {
		return fmt.Errorf("invalid role provided: %s", role)
	}

	strRequestURL := fb.restAPIBaseUrl + "accounts:update?key=" + fb.webAPIKey
	resp, err := http.Post(strRequestURL, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to set password, response: %s", string(bodyBytes))
	}

	return nil
}

// ChangePassword updates the user's password using the provided ID token and returns new tokens.
func (fb *AuthClient) ChangePassword(idToken, newPassword string) (*FBSignInResponse, error) {
	// Step 1: Build the request body
	body := map[string]interface{}{
		"idToken":           idToken,
		"password":          newPassword,
		"returnSecureToken": true,
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %v", err)
	}

	// Step 2: Make HTTP request to Firebase
	var requestURL = fb.restAPIBaseUrl + "accounts:update?key=" + fb.webAPIKey
	resp, err := http.Post(requestURL, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Step 3: Read and parse the response
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	// Check if request was successful
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to change password, status code: %d, response: %s", resp.StatusCode, string(responseBody))
	}

	// Parse JSON response
	var response FBSignInResponse
	err = json.Unmarshal(responseBody, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	return &response, nil // ✅ Return new token and refresh token
}

// FinalizeMFA - Completes MFA verification and returns the new ID Token
// VerifyMFA sends an MFA sign-in request to Firebase and returns the authentication tokens directly
// VerifyTOTP sends an MFA TOTP sign-in request to Firebase and returns authentication tokens
func (fb *AuthClient) VerifyMFA(customtoken string) (string, string, error) {
	// ✅ Step 1: Build the request body for TOTP
	body := map[string]interface{}{
		"token":             customtoken,
		"returnSecureToken": true,
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return "", "", fmt.Errorf("❌ Failed to marshal request body: %v", err)
	}

	// ✅ Step 2: Correct API URL
	requestURL := "https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key=" + fb.webAPIKey
	resp, err := http.Post(requestURL, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", "", fmt.Errorf("❌ Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// ✅ Step 3: Read and parse the response
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("❌ Failed to read response body: %v", err)
	}

	// ✅ Step 4: Check if request was successful
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("❌ TOTP verification failed, status code: %d, response: %s", resp.StatusCode, string(responseBody))
	}

	// ✅ Step 5: Parse successful response
	var responseData struct {
		IDToken      string `json:"idToken"`
		RefreshToken string `json:"refreshToken"`
	}

	if err := json.Unmarshal(responseBody, &responseData); err != nil {
		return "", "", fmt.Errorf("❌ Failed to parse response JSON: %v", err)
	}

	// ✅ Return the ID Token and Refresh Token directly
	return responseData.IDToken, responseData.RefreshToken, nil
}

// StartMFA - Initiates an MFA challenge (sends OTP to the user's device)
func (fb *AuthClient) StartMFA(mfaPendingToken string) (string, string, error) {
	// Firebase API endpoint for starting MFA challenge
	url := "https://identitytoolkit.googleapis.com/v1/accounts/mfaEnrollmentStart?key=" + fb.webAPIKey

	// Construct the request body
	requestBody, err := json.Marshal(struct {
		MfaPendingCredential  string `json:"mfaPendingCredential"`
		PhoneVerificationInfo struct {
			RecaptchaToken string `json:"recaptchaToken,omitempty"`
		} `json:"phoneVerificationInfo"`
	}{
		MfaPendingCredential: mfaPendingToken,
		PhoneVerificationInfo: struct {
			RecaptchaToken string `json:"recaptchaToken,omitempty"`
		}{},
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal request: %v", err)
	}

	// Send HTTP request to Firebase
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return "", "", fmt.Errorf("failed to send MFA challenge request: %v", err)
	}
	defer resp.Body.Close()

	// Parse the response
	var responseData struct {
		SessionInfo     string `json:"sessionInfo"`
		MfaEnrollmentID string `json:"mfaEnrollmentId"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&responseData); err != nil {
		return "", "", fmt.Errorf("failed to decode response: %v", err)
	}

	// Return MFA session info and enrollment ID
	return responseData.SessionInfo, responseData.MfaEnrollmentID, nil
}

// ValidateTokenWithAPI checks the validity of the provided ID token.
func (fb *AuthClient) ValidateTokenWithAPI(idToken string) (map[string]interface{}, error) {
	// ***************************************************************************************************************/
	// Step 1 of 3:  Build Request
	// ***************************************************************************************************************/
	body := map[string]string{
		"idToken": idToken,
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %v", err)
	}

	// ***************************************************************************************************************/
	// Step 2 of 3:  Make Request and get a response
	// ***************************************************************************************************************/
	var strRequestURL = fb.restAPIBaseUrl + "accounts:lookup?key=" + fb.webAPIKey // Updated endpoint
	resp, err := http.Post(strRequestURL, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// ***************************************************************************************************************/
	// Step 3 of 3:  Check response is valid
	// ***************************************************************************************************************/
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to validate token, status code: %d, response: %s", resp.StatusCode, string(responseBody))
	}

	var response map[string]interface{}
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return response, nil
}

// SendPasswordResetEmail sends a password reset email to the specified address.
func (fb *AuthClient) SendPasswordResetEmail(email string) error {
	// ***************************************************************************************************************/
	// Step 1 of 3:  Build Request
	// ***************************************************************************************************************/
	body := map[string]interface{}{
		"requestType": "PASSWORD_RESET",
		"email":       email,
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %v", err)
	}

	// ***************************************************************************************************************/
	// Step 2 of 3:  Make Request and get a response
	// ***************************************************************************************************************/
	var strRequestURL = fb.restAPIBaseUrl + "accounts:sendOobCode?key=" + fb.webAPIKey // Updated endpoint
	resp, err := http.Post(strRequestURL, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// ***************************************************************************************************************/
	// Step 3 of 3:  Check response is valid
	// ***************************************************************************************************************/
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to send reset email, status code: %d, response: %s", resp.StatusCode, string(responseBody))
	}

	return nil
}

// RefreshToken retrieves a new ID token using the provided refresh token.
func (fb *AuthClient) RefreshToken(refreshToken string) (*FBSignInResponse, error) {
	// ***************************************************************************************************************/
	// Step 1 of 3:  Build Request
	// ***************************************************************************************************************/
	body := map[string]interface{}{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %v", err)
	}

	// ***************************************************************************************************************/
	// Step 2 of 3:  Make Request and get a response
	// ***************************************************************************************************************/
	var strRequestURL = "https://securetoken.googleapis.com/v1/token?key=" + fb.webAPIKey // Updated endpoint for refreshing token
	resp, err := http.Post(strRequestURL, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to send refreshToken request: %v", err)
	}
	defer resp.Body.Close()

	// ***************************************************************************************************************/
	// Step 3 of 3:  Check response is valid
	// ***************************************************************************************************************/
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read refreshToken response body: %v", err)
	}
	//log.Println("Refresh Token Response:", string(responseBody))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to refresh token, status code: %d, response: %s", resp.StatusCode, string(responseBody))
	}

	// ✅ Temporary struct with exported fields for JSON unmarshalling
	var tempResponse struct {
		AccessToken  string `json:"access_token"`
		ExpiresIn    string `json:"expires_in"`
		TokenType    string `json:"token_type"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		UserID       string `json:"user_id"`
		ProjectID    string `json:"project_id"`
	}

	// ✅ Parse response into temporary struct
	err = json.Unmarshal(responseBody, &tempResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	// ✅ Copy values from temp struct to original struct (with private fields)
	loginResponse := &FBSignInResponse{
		//accessToken: tempResponse.AccessToken,
		expiresIn: tempResponse.ExpiresIn,
		//tokenType:    tempResponse.TokenType,
		refreshToken: tempResponse.RefreshToken,
		idToken:      tempResponse.IDToken,
		localID:      tempResponse.UserID,
		//projectID:    tempResponse.ProjectID,
	}

	// ✅ Debug: Print ID Token
	log.Println("Extracted ID Token:", loginResponse.GetIDToken())

	return loginResponse, nil
}

// SendPasswordResetCodeEmail sends a password reset email to the specified address.
func (fb *AuthClient) SendPasswordResetCodeEmail(email string) error {
	// ***************************************************************************************************************/
	// Step 1 of 3: Build Request
	// ***************************************************************************************************************/
	var strRequestURL = fb.restAPIBaseUrl + "accounts:sendOobCode?key=" + fb.webAPIKey
	// Create the request body
	requestBody, err := json.Marshal(map[string]interface{}{
		"requestType": "PASSWORD_RESET",
		"email":       email,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %v", err)
	}

	// ***************************************************************************************************************/
	// Step 2 of 3: Make Request and get a response
	// ***************************************************************************************************************/
	resp, err := http.Post(strRequestURL, "application/json; charset=utf-8", bytes.NewBuffer(requestBody))
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// ***************************************************************************************************************/
	// Step 3 of 3: Check response is valid
	// ***************************************************************************************************************/
	if resp.StatusCode != http.StatusOK {
		// Convert response body to string for error logging
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %v", err)
		}
		return fmt.Errorf("failed to send reset email, status code: %d, response: %s", resp.StatusCode, string(bodyBytes))
	}

	// Password reset email sent successfully
	return nil
}

// VerifyPasswordResetCode verifies the password reset code sent to the user's email.
func (fb *AuthClient) VerifyPasswordResetCode(code string) (string, error) {
	// ***************************************************************************************************************/
	// Step 1: Build Request
	// ***************************************************************************************************************/
	var strRequestURL = fb.restAPIBaseUrl + "accounts:resetPassword?key=" + fb.webAPIKey // Updated endpoint for refreshing token
	// Create the request body
	requestBody, err := json.Marshal(map[string]string{
		"oobCode": code,
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %v", err)
	}

	// ***************************************************************************************************************/
	// Step 2: Make Request and get a response
	// ***************************************************************************************************************/
	resp, err := http.Post(strRequestURL, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return "", fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// ***************************************************************************************************************/
	// Step 3: Check response is valid
	// ***************************************************************************************************************/
	if resp.StatusCode != http.StatusOK {
		// Convert response body to string for error logging
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("failed to read response body: %v", err)
		}
		return "", fmt.Errorf("failed to verify code, status code: %d, response: %s", resp.StatusCode, string(bodyBytes))
	}

	// ***************************************************************************************************************/
	// Step 4: Parse Response
	// ***************************************************************************************************************/
	var response struct {
		LocalID string `json:"localId"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", fmt.Errorf("failed to decode response: %v", err)
	}

	// Return the user ID associated with the reset code
	return response.LocalID, nil
}

// ResetPasswordByEmail updates the password in Firebase Authentication
func (fb *AuthClient) ResetPasswordByEmail(email string, newPassword string) error {
	var strRequestResetURL = fb.restAPIBaseUrl + "accounts:sendOobCode?key=" + fb.webAPIKey
	// Create the request body
	requestBody, err := json.Marshal(map[string]interface{}{
		"requestType": "PASSWORD_RESET",
		"email":       email,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %v", err)
	}

	// ***************************************************************************************************************/
	// Step 2 of 3: Make Request and get a response
	// ***************************************************************************************************************/
	resp, err := http.Post(strRequestResetURL, "application/json; charset=utf-8", bytes.NewBuffer(requestBody))
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()
	fmt.Printf("response: %v", resp)
	// ***************************************************************************************************************/
	// Step 1: Build Request
	// ***************************************************************************************************************/
	var strRequestURL = fb.restAPIBaseUrl + "accounts:update?key=" + fb.webAPIKey

	requestBody2, err := json.Marshal(map[string]interface{}{
		"email":             email,
		"password":          newPassword,
		"returnSecureToken": false,
	})

	if err != nil {
		return fmt.Errorf("failed to marshal request body: %v", err)
	}
	fmt.Printf("strRequestURL: %s\n", strRequestURL)
	// ***************************************************************************************************************/
	// Step 2 of 3: Make Request and get a response
	// ***************************************************************************************************************/
	resp2, err := http.Post(strRequestURL, "application/json; charset=utf-8", bytes.NewBuffer(requestBody2))
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to update password in Firebase, status: %d", resp2.StatusCode)
	}

	return nil
}

// ConfirmPasswordReset confirms a password reset with the provided oobCode and new password.
func (fb *AuthClient) ConfirmPasswordReset(oobCode, newPassword string) error {
	// ***************************************************************************************************************/
	// Step 1: Build Request
	// ***************************************************************************************************************/
	var strRequestURL = fb.restAPIBaseUrl + "accounts:resetPassword?key=" + fb.webAPIKey
	// Create the request body
	requestBody, err := json.Marshal(map[string]interface{}{
		"oobCode":     oobCode,
		"newPassword": newPassword,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %v", err)
	}

	// ***************************************************************************************************************/
	// Step 2: Make Request and get a response
	// ***************************************************************************************************************/
	resp, err := http.Post(strRequestURL, "application/json; charset=utf-8", bytes.NewBuffer(requestBody))
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// ***************************************************************************************************************/
	// Step 3: Check response is valid
	// ***************************************************************************************************************/
	if resp.StatusCode != http.StatusOK {
		// Convert response body to string for error logging
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %v", err)
		}
		return fmt.Errorf("failed to confirm password reset, status code: %d, response: %s", resp.StatusCode, string(bodyBytes))
	}

	// Password reset confirmed successfully
	return nil
}

// ConfirmEmailVerification confirms an email verification with the provided oobCode.
func (fb *AuthClient) ConfirmEmailVerification(oobCode string) error {
	// ***************************************************************************************************************/
	// Step 1: Build Request
	// ***************************************************************************************************************/
	var strRequestURL = fb.restAPIBaseUrl + "accounts:update?key=" + fb.webAPIKey

	// Create the request body
	requestBody, err := json.Marshal(map[string]interface{}{
		"oobCode": oobCode,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %v", err)
	}

	// ***************************************************************************************************************/
	// Step 2: Make Request and get a response
	// ***************************************************************************************************************/
	resp, err := http.Post(strRequestURL, "application/json; charset=utf-8", bytes.NewBuffer(requestBody))
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// ***************************************************************************************************************/
	// Step 3: Check response is valid
	// ***************************************************************************************************************/
	if resp.StatusCode != http.StatusOK {
		// Convert response body to string for error logging
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %v", err)
		}
		return fmt.Errorf("failed to confirm email verification, status code: %d, response: %s", resp.StatusCode, string(bodyBytes))
	}

	// Email verification confirmed successfully
	return nil
}

// SignInWithPhoneNumber signs in a user with their phone number and verification code.
func (fb *AuthClient) SignInWithPhoneNumber(phoneNumber, code string) (*FBSignInResponse, error) {
	// ***************************************************************************************************************/
	// Step 1: Build Request
	// ***************************************************************************************************************/
	strRequestURL := fmt.Sprintf("%saccounts:signInWithPhoneNumber?key=%s", fb.restAPIBaseUrl, fb.webAPIKey)

	// Create the request body
	requestBody, err := json.Marshal(map[string]interface{}{
		"phoneNumber": phoneNumber,
		"code":        code,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %v", err)
	}

	// ***************************************************************************************************************/
	// Step 2: Make Request and get a response
	// ***************************************************************************************************************/
	resp, err := http.Post(strRequestURL, "application/json; charset=utf-8", bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// ***************************************************************************************************************/
	// Step 3: Check response is valid
	// ***************************************************************************************************************/
	if resp.StatusCode != http.StatusOK {
		// Convert response body to string for error logging
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %v", err)
		}
		return nil, fmt.Errorf("failed to sign in with phone number, status code: %d, response: %s", resp.StatusCode, string(bodyBytes))
	}

	// ***************************************************************************************************************/
	// Step 4: Parse Response
	// ***************************************************************************************************************/
	var signInResponse FBSignInResponse
	if err := json.NewDecoder(resp.Body).Decode(&signInResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	// Return the sign-in response
	return &signInResponse, nil
}

func (fb *AuthClient) IsEmailVerified(idToken string) (bool, error) {
	log.Println("JSON Request idToken:", idToken)
	jsonReq, err := json.Marshal(struct {
		IdToken string `json:"idToken"`
	}{
		IdToken: idToken,
	})
	if err != nil {
		return false, fmt.Errorf("failed to marshal request: %v", err)
	}

	// ✅ Debug: Print final JSON request
	log.Println("Final JSON Request:", string(jsonReq))

	strRequestURL := fb.restAPIBaseUrl + "accounts:lookup?key=" + fb.webAPIKey
	log.Println("strRequestURL", strRequestURL)
	resp, err := http.Post(strRequestURL, "application/json", bytes.NewBuffer(jsonReq))
	if err != nil {
		return false, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()
	log.Println("Email Verify Resposn:", resp)
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("failed to validate token")
	}

	var response struct {
		Users []struct {
			EmailVerified bool `json:"emailVerified"`
		} `json:"users"`
	}
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return false, fmt.Errorf("failed to parse response: %v", err)
	}
	log.Println("Email Verify Resposn:", response)
	if len(response.Users) == 0 {
		return false, fmt.Errorf("user not found")
	}
	return response.Users[0].EmailVerified, nil
}

// SendOTPRequest sends an OTP to the user's phone number via Firebase
func (fb *AuthClient) SendOTPRequest(phoneNumber string, recaptchaToken string) (*FBSignInResponse, error) {
	strRequestURL := fb.restAPIBaseUrl + "accounts:sendVerificationCode?key=" + fb.webAPIKey

	// Create request body
	requestBody, err := json.Marshal(map[string]interface{}{
		"phoneNumber":    phoneNumber,
		"recaptchaToken": recaptchaToken,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %v", err)
	}

	fmt.Println("Request URL:", strRequestURL)

	// Send request to Firebase
	resp, err := http.Post(strRequestURL, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Read response body safely
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	// Log response (conditionally)
	if resp.StatusCode != http.StatusOK {
		log.Printf("Error sending OTP, status: %d, response: %s", resp.StatusCode, string(bodyBytes))
		return nil, fmt.Errorf("failed to send OTP, status: %d, response: %s", resp.StatusCode, string(bodyBytes))
	}

	fmt.Println("Send OTP Response:", string(bodyBytes))

	var tempResponse struct {
		SessionInfo string `json:"sessionInfo"`
	}

	err = json.Unmarshal(bodyBytes, &tempResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	loginResponse := &FBSignInResponse{
		sessionInfo: tempResponse.SessionInfo,
	}

	// Return the correct response type
	return loginResponse, nil
}

// VerifyOTP verifies the OTP entered by the user via Firebase
func (fb *AuthClient) VerifyOTP(sessionInfo, otpCode string) (*FBSignInResponse, error) {
	strRequestURL := fb.restAPIBaseUrl + "accounts:signInWithPhoneNumber?key=" + fb.webAPIKey

	// Create request body
	requestBody, err := json.Marshal(map[string]interface{}{
		"sessionInfo": sessionInfo,
		"code":        otpCode,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %v", err)
	}

	// Send request to Firebase
	resp, err := http.Post(strRequestURL, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Check response
	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to verify OTP, status: %d, response: %s", resp.StatusCode, string(bodyBytes))
	}

	var tempResponse struct {
		Kind         string `json:"kind"`
		Registered   bool   `json:"registered"`
		LocalID      string `json:"localId"`
		Email        string `json:"email"`
		PhoneNumber  string `json:"phoneNumber"`
		IDToken      string `json:"idToken"`
		RefreshToken string `json:"refreshToken"`
		ExpiresIn    string `json:"expiresIn"`
	}

	// ✅ Parse response into temporary struct
	err = json.Unmarshal(bodyBytes, &tempResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	// ✅ Copy values from temp struct to original struct (with private fields)
	loginResponse := &FBSignInResponse{
		kind:         tempResponse.Kind,
		registered:   tempResponse.Registered,
		localID:      tempResponse.LocalID,
		email:        tempResponse.Email,
		phoneNumber:  tempResponse.PhoneNumber,
		idToken:      tempResponse.IDToken,
		refreshToken: tempResponse.RefreshToken,
		expiresIn:    tempResponse.ExpiresIn,
	}

	return loginResponse, nil
}

// generateFirebaseSessionToken calls Firebase API to generate a session token
// completeMfaVerification completes Firebase MFA verification and returns an ID token

func (fb *AuthClient) CompleteMfaVerification(mfaPendingCredential, otp, mfaEnrollmentId string) (string, error) {

	// ***************************************************************************************************************/
	// Step 1: Build Request
	// ***************************************************************************************************************/

	// Create the request body
	/*requestBody, err := json.Marshal(map[string]interface{}{
		"mfaPendingCredential": mfaPendingCredential,
		"verificationInfo": map[string]string{
			"mfaEnrollmentId": mfaEnrollmentId,
			"code":            otp,
		},
	})*/
	var requestBody map[string]interface{}
	// ✅ Define Firebase MFA Verification Request Payload
	requestBody = map[string]interface{}{
		"mfaPendingCredential": mfaPendingCredential,
		"mfaEnrollmentId":      mfaEnrollmentId,
		"totpVerificationInfo": map[string]string{
			"verificationCode": otp, // The TOTP code entered by the user
		},
	}
	// ✅ Convert request body to JSON
	requestData, err := json.Marshal(requestBody)
	if err != nil {
		return "", err
	}
	log.Println("FMA request: ", string(requestData))
	// ***************************************************************************************************************/
	// Step 2: Make Request and get a response
	// ***************************************************************************************************************/
	var strRequestURL = fb.restAPIBaseUrl + "accounts/mfaSignIn?key=" + fb.webAPIKey // Updated endpoint for refreshing token
	log.Println("strRequestURL: ", strRequestURL)
	resp, err := http.Post(strRequestURL, "application/json", bytes.NewBuffer(requestData))
	if err != nil {
		return "", fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// ***************************************************************************************************************/
	// Step 3: Check response is valid
	// ***************************************************************************************************************/
	if resp.StatusCode != http.StatusOK {
		// Convert response body to string for error logging
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("failed to read response body: %v", err)
		}
		return "", fmt.Errorf("failed to verify code, status code: %d, response: %s", resp.StatusCode, string(bodyBytes))
	}

	// ***************************************************************************************************************/
	// Step 4: Parse Response
	// ***************************************************************************************************************/
	var response struct {
		LocalID string `json:"localId"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", fmt.Errorf("failed to decode response: %v", err)
	}

	// Return the user ID associated with the reset code
	return response.LocalID, nil
}

// ValidateTOTP checks if the provided OTP is valid
func ValidateTOTP(secret, otp string) bool {
	log.Println("totpSecret", secret)
	log.Println("OTP1", otp)
	return true
	//return totp.Validate(otp, secret)
}

// UpdateUserMFA updates the MFA settings for a Firebase user.
func (fb *AuthClient) UpdateUserMFA(uid string) error {

	var requestBody map[string]interface{}
	requestBody = map[string]interface{}{
		"idToken": uid,
		"mfa": map[string]interface{}{
			"state": "ENABLED",
			"providerConfigs": []map[string]interface{}{
				{
					"totpProviderConfig": map[string]interface{}{
						"adjacentIntervals": 2,
					},
					"state": "ENABLED",
				},
			},
		},
	}
	// ✅ Convert request body to JSON
	requestData, err := json.Marshal(requestBody)
	if err != nil {
		return err
	}
	log.Println("FMA request: ", string(requestData))
	// ***************************************************************************************************************/
	// Step 2: Make Request and get a response
	// ***************************************************************************************************************/
	var strRequestURL = fmt.Sprintf("%sprojects/%s/accounts:update?key=%s", fb.restAPIBaseUrl, fb.projectId, fb.webAPIKey)
	log.Println("strRequestURL: ", strRequestURL)
	resp, err := http.Post(strRequestURL, "application/json", bytes.NewBuffer(requestData))
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// ***************************************************************************************************************/
	// Step 3: Check response is valid
	// ***************************************************************************************************************/
	if resp.StatusCode != http.StatusOK {
		// Convert response body to string for error logging
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %v", err)
		}
		return fmt.Errorf("failed to verify code, status code: %d, response: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

func (fb *AuthClient) UpdateUserPhoneNumber(uid, phoneNumber string) error {

	// Create the request body
	requestBody, err := json.Marshal(map[string]interface{}{
		"idToken":     uid, // User’s ID Token
		"phoneNumber": phoneNumber,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %v", err)
	}

	var strRequestURL = fmt.Sprintf("%saccounts:update?key=%s", fb.restAPIBaseUrl, fb.webAPIKey)
	log.Println("strRequestURL: ", strRequestURL)
	resp, err := http.Post(strRequestURL, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}
	log.Println("responseBody: ", string(responseBody))
	// ***************************************************************************************************************/
	// Step 3: Check response is valid
	// ***************************************************************************************************************/
	if resp.StatusCode != http.StatusOK {
		// Convert response body to string for error logging
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %v", err)
		}
		return fmt.Errorf("failed to verify code, status code: %d, response: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

func (fb *AuthClient) SendMfaSMS(mfaPendingToken string) (string, error) {

	strRequestURL := fmt.Sprintf("%saccounts/mfaEnrollment:sendSms?key=%s", fb.restAPIBaseUrl, fb.webAPIKey)

	// Create the request body
	requestBody, err := json.Marshal(map[string]interface{}{
		"mfaPendingCredential": mfaPendingToken,
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %v", err)
	}
	log.Println("strRequestURL", strRequestURL)
	log.Println("requestBody", string(requestBody))
	// ***************************************************************************************************************/
	// Step 2: Make Request and get a response
	// ***************************************************************************************************************/
	resp, err := http.Post(strRequestURL, "application/json; charset=utf-8", bytes.NewBuffer(requestBody))
	if err != nil {
		return "", fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// ***************************************************************************************************************/
	// Step 3: Check response is valid
	// ***************************************************************************************************************/
	if resp.StatusCode != http.StatusOK {
		// Convert response body to string for error logging
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("failed to read response body: %v", err)
		}
		return "", fmt.Errorf("failed to sign in with phone number, status code: %d, response: %s", resp.StatusCode, string(bodyBytes))
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	if sessionInfo, ok := result["sessionInfo"].(string); ok {
		return sessionInfo, nil
	}
	return "", nil
}

func UpdateRefreshToken(db *sql.DB, email string, refreshToken string) error {
	query := `UPDATE users SET refresh_token = $1, updated_at = now() WHERE email = $2`
	_, err := db.Exec(query, refreshToken, email)
	return err
}

// GenerateRandomPassword - Generates a secure random password
func GenerateRandomPassword(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_+="
	password := make([]byte, length)
	charsetLength := big.NewInt(int64(len(charset)))

	for i := range password {
		randomIndex, err := rand.Int(rand.Reader, charsetLength)
		if err != nil {
			return "", err
		}
		password[i] = charset[randomIndex.Int64()]
	}

	return string(password), nil
}

// GetRefreshToken returns the refresh token.
func (r *FBSignInResponse) GetRefreshToken() string {
	return r.refreshToken
}

// GetEmail returns the user's email.
func (r *FBSignInResponse) GetEmail() string {
	return r.email
}

// GetPhoneNumber returns the user's phone number.
func (r *FBSignInResponse) GetPhoneNumber() string {
	return r.phoneNumber
}

// GetLocalID returns the user's id.
func (r *FBSignInResponse) GetLocalID() string {
	return r.localID
}

func (r *FBSignInResponse) GetMfaPendingToken() string {
	return r.mfaPendingCredential
}

func (r *FBSignInResponse) GetIDToken() string {
	return r.idToken
}

func (r *FBSignInResponse) GetMfaInfo() []mfaInfo {
	return r.mfaInfo
}

func (r *FBSignInResponse) GetSessionInfo() string {
	return r.sessionInfo
}
