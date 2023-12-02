package main

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math"
	"math/big"
	"net/http"
	"os"
	"sync"

	"github.com/TrustedPay/tp-term/pkg/tpterm"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type ExampleBank struct {
	Nonces   *sync.Map
	Accounts map[string]*Account
}

type Account struct {
	TrustedKey crypto.PublicKey
	CardNumber string
	Expiration string
	Balance    int64
}

type AuthorizeRequest struct {
	TransactionID string              `json:"transactionId"`
	Request       *tpterm.Transaction `json:"req"`
	Signature     []byte              `json:"signature"`
}

func (eb *ExampleBank) GenerateNonceHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Use /dev/urandom as entropy source
		urandom, err := os.Open("/dev/urandom")
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		// Generate random nonce
		nonce, err := rand.Int(urandom, big.NewInt(math.MaxInt64))
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		// Assign a transaction ID
		transactionID := uuid.NewString()

		// Store this in nonce map
		eb.Nonces.Store(transactionID, nonce)

		logrus.Infof("Generated nonce %d for transaction %s", nonce, transactionID)

		// Return nonce and transaction ID
		c.JSON(http.StatusOK, gin.H{
			"transactionId": transactionID,
			"nonce":         nonce,
		})
	}
}

func (eb *ExampleBank) AuthorizeHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Unmarshal the JSON request body
		var request AuthorizeRequest
		if err := c.Bind(&request); err != nil {
			logrus.Errorf("%v", err)
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		// Check this transaction has been initialized
		nonce, ok := eb.Nonces.Load(request.TransactionID)
		if !ok {
			logrus.Errorf("Bad transaction ID of %s", request.TransactionID)
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "bad transaction ID"})
			return
		}
		logrus.Printf("Got transaction %s", request.TransactionID)

		// Check the nonces match
		if big.NewInt(request.Request.Nonce).Cmp(nonce.(*big.Int)) != 0 {
			logrus.Errorf("Request nonce (%d) doesn't match stored nonce (%d)", request.Request.Nonce, nonce.(*big.Int))
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		logrus.Printf("Nonces match! (%d=%d)", request.Request.Nonce, nonce.(*big.Int))

		// Get the account from the internal map
		account, ok := eb.Accounts[request.Request.CardNumber]
		if !ok {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "card number is invalid"})
			return
		}

		// Check card info
		if account.CardNumber != request.Request.CardNumber {
			logrus.Errorf("Card number is invalid")
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		if account.Expiration != request.Request.CardExp {
			logrus.Errorf("Card expiration is invalid")
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		logrus.Infof("Card info is valid!")

		// Generate a digest for the request
		dataBytes, err := json.Marshal(&request.Request)
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		hash := crypto.SHA256.New()
		hash.Write(dataBytes)
		digest := hash.Sum(nil)

		// Verify the signature is valid from the trusted key
		if !ecdsa.VerifyASN1(account.TrustedKey.(*ecdsa.PublicKey), digest, request.Signature) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "transaction signature is invalid"})
			return
		}
		logrus.Printf("Signature is valid!")

		// If transaction is valid, process it
		if eb.Accounts[request.Request.CardNumber].Balance < request.Request.Amount {
			logrus.Warnf("Not enough funds (need $%.2f, have $%.2f)", float64(eb.Accounts[request.Request.CardNumber].Balance)/100, float64(request.Request.Amount)/100)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "not enough funds"})
			return
		} else {
			prevBalance := eb.Accounts[request.Request.CardNumber].Balance
			eb.Accounts[request.Request.CardNumber].Balance -= request.Request.Amount
			logrus.WithFields(logrus.Fields{
				"prev_balance": prevBalance,
				"new_balance":  eb.Accounts[request.Request.CardNumber].Balance,
			}).Printf("Transaction approved!")
		}

		// Delete the transaction nonce
		eb.Nonces.Delete(request.TransactionID)

		c.JSON(http.StatusOK, gin.H{
			"transactionId": request.TransactionID,
		})
	}
}

func main() {
	gin.SetMode(gin.ReleaseMode)

	r := gin.Default()

	logrus.Printf("Please paste the trusted public key here and press [enter] to continue:\n")
	pubKey := ""
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		text := scanner.Text()
		pubKey += text + "\n"
		if text == "-----END PUBLIC KEY-----" {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		logrus.Errorf("%v", err)
	}
	pemBlock, _ := pem.Decode([]byte(pubKey))
	if pemBlock == nil {
		logrus.Fatalf("PEM formatted block not found")
	}
	parsedKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		logrus.Fatalf("failed to parse public key: %v", err)
	}
	trustedKey, ok := parsedKey.(crypto.PublicKey)
	if !ok {
		logrus.Fatalf("public key not of expected type crypto.PublicKey")
	}
	logrus.Printf("Ready to accept connections!")

	eb := &ExampleBank{
		Nonces: &sync.Map{},
		Accounts: map[string]*Account{
			"8888888888888888": {
				TrustedKey: trustedKey,
				CardNumber: "8888888888888888",
				Expiration: "01/99",
				Balance:    10000,
			},
		},
	}

	r.GET("/transaction/initialize", eb.GenerateNonceHandler())
	r.POST("/transaction/authorize", eb.AuthorizeHandler())

	r.Run(":8080")
}
