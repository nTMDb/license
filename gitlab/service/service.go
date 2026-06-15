package service

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"license/config"
	"license/crypto"
	"license/gitlab/entity"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	gorsa "github.com/Lyafei/go-rsa"
	"github.com/gin-gonic/gin"
)

// License quantity granted by the generated license.
const licenseQuantity = 1000

// KeyManager manages RSA keys with lazy loading and caching
type KeyManager struct {
	privateKey []byte
	publicKey  []byte
	once       sync.Once
	mutex      sync.RWMutex
	err        error
}

var keyManager = &KeyManager{}

// getKeys returns cached keys with lazy loading
func (km *KeyManager) getKeys() ([]byte, []byte, error) {
	km.once.Do(func() {
		if publicBytes, err := os.ReadFile(config.GetConfig().DataDir + "/.license_encryption_key.pub"); err == nil {
			km.publicKey = publicBytes
		} else {
			km.err = fmt.Errorf("failed to read public key: %v", err)
			return
		}
		if privateBytes, err := os.ReadFile(config.GetConfig().DataDir + "/.license_decryption_key.pri"); err == nil {
			km.privateKey = privateBytes
		} else {
			km.err = fmt.Errorf("failed to read private key: %v", err)
			return
		}
	})

	km.mutex.RLock()
	defer km.mutex.RUnlock()
	return km.privateKey, km.publicKey, km.err
}

// LoadKeys initializes the key manager (for backward compatibility)
func LoadKeys() error {
	_, _, err := keyManager.getKeys()
	return err
}

// Buffer pools for efficient memory management
var (
	jsonBufferPool = sync.Pool{
		New: func() interface{} {
			return bytes.NewBuffer(make([]byte, 0, 4096))
		},
	}
	ioBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 32*1024) // 32KB buffer
		},
	}
	aesKeyPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 16)
		},
	}
	ivPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, aes.BlockSize)
		},
	}
)

// newLicenseIdentifiers returns a freshly randomized set of identifiers (restriction id,
// subscription id/name and per-add-on purchase XIDs) so every generated license carries
// a unique identity. A single rand.Read call backs all values.
func newLicenseIdentifiers() (restrictionID, subID, subName, duoXID, dapXID string, err error) {
	var buf [40]byte
	if _, err = rand.Read(buf[:]); err != nil {
		return "", "", "", "", "", err
	}
	restrictionID = fmt.Sprintf("%x", buf[0:8])
	subID = fmt.Sprintf("offline-subscription-%x", buf[8:16])
	subName = fmt.Sprintf("ultimate-duo-self-hosted-%x", buf[16:24])
	duoXID = fmt.Sprintf("duo-enterprise-%x", buf[24:32])
	dapXID = fmt.Sprintf("self-hosted-dap-%x", buf[32:40])
	return
}

// createLicenseJson creates a JSON representation of the license with optimized buffer usage.
// The payload follows GitLab's cloud / offline-cloud licensing schema (GitLab 17+):
// it carries activation timestamps, subscription metadata and add_on_products instead of
// the legacy top-level features whitelist.
func createLicenseJson(licenseInfo entity.LicenseInfo, expireTime string) ([]byte, error) {

	var expirationDate time.Time
	var err error
	if len(expireTime) == 0 {
		// Default expiration time is 2 years
		expirationDate = time.Now().AddDate(2, 0, 0)
	} else {
		expirationDate, err = time.Parse(time.DateTime, expireTime)
		if err != nil {
			log.Printf("Failed to parse expiration time: %v", err)
			return nil, err
		}
	}

	restrictionID, subID, subName, duoXID, dapXID, err := newLicenseIdentifiers()
	if err != nil {
		log.Printf("Failed to generate license identifiers: %v", err)
		return nil, err
	}

	now := time.Now()
	// activated_at is conventionally the day after issuance, normalized to 00:00 UTC.
	activatedAt := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)

	addOnProducts := map[string][]entity.AddOnPurchase{
		"duo_enterprise": {{
			Quantity:    licenseQuantity,
			StartedOn:   entity.CustomTime{Time: now},
			ExpiresOn:   entity.CustomTime{Time: expirationDate},
			PurchaseXID: duoXID,
		}},
		"self_hosted_dap": {{
			Quantity:    1,
			StartedOn:   entity.CustomTime{Time: now},
			ExpiresOn:   entity.CustomTime{Time: expirationDate},
			PurchaseXID: dapXID,
		}},
	}

	license := entity.License{
		Version: 1,
		License: licenseInfo,

		IssuedAt:       entity.CustomTime{Time: now},
		ExpiresAt:      entity.CustomTime{Time: expirationDate},
		NotifyAdminsAt: entity.CustomTime{Time: expirationDate.AddDate(0, 0, -30)},
		NotifyUsersAt:  entity.CustomTime{Time: expirationDate.AddDate(0, 0, -7)},
		BlockChangesAt: entity.CustomTime{Time: expirationDate.AddDate(0, 0, 180)},

		ActivatedAt:  entity.CustomDateTime{Time: activatedAt},
		LastSyncedAt: entity.CustomDateTime{Time: activatedAt},
		NextSyncAt:   entity.CustomDateTime{Time: activatedAt.AddDate(0, 0, 90)},

		CloudLicensingEnabled:        true,
		OfflineCloudLicensingEnabled: true,
		AutoRenewEnabled:             false,
		SeatReconciliationEnabled:    true,
		OperationalMetricsEnabled:    true,
		GeneratedFromCustomersDot:    true,
		GeneratedFromCancellation:    false,
		TemporaryExtension:           false,
		ContractOveragesAllowed:      true,

		Restrictions: entity.Restriction{
			ID:                      restrictionID,
			Plan:                    "ultimate",
			ActiveUserCount:         licenseQuantity,
			SubscriptionID:          subID,
			SubscriptionName:        subName,
			ReconciliationCompleted: true,
			AddOnProducts:           addOnProducts,
		},
	}

	buf := jsonBufferPool.Get().(*bytes.Buffer)
	defer func() {
		buf.Reset()
		jsonBufferPool.Put(buf)
	}()

	encoder := json.NewEncoder(buf)
	// Match Ruby's JSON.dump output: don't escape <, >, & as \u003c, \u003e, \u0026.
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(license); err != nil {
		return nil, err
	}

	// Remove trailing newline added by encoder
	data := buf.Bytes()
	if len(data) > 0 && data[len(data)-1] == '\n' {
		data = data[:len(data)-1]
	}

	result := make([]byte, len(data))
	copy(result, data)
	return result, nil
}

// generateRandomIV generates a random initialization vector (IV)
func generateRandomIV() ([]byte, error) {
	iv := make([]byte, aes.BlockSize) // AES block size is fixed at 16 bytes
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	return iv, nil
}

// Encrypt wraps the Encrypt method, using AES-CBC encryption and PKCS7 padding
func Encrypt(data, key, iv []byte) ([]byte, error) {
	aesTool := crypto.AesCbcPkcs7{Key: key, Iv: iv}
	enc, err := aesTool.Encrypt(data)
	if err != nil {
		log.Println("Encrypt error:", err)
		return nil, err
	}
	return enc, err
}

// Uses RSA private key to "encrypt" data with cached keys
func encryptWithPrivateKey(data string) (string, error) {
	privateKey, _, err := keyManager.getKeys()
	if err != nil {
		return "", err
	}
	encrypt, err := gorsa.PriKeyEncrypt(data, string(privateKey))
	if err != nil {
		log.Printf("Failed to encrypt data with RSA private key: %v", err)
		return "", err
	}
	return encrypt, nil
}

// encryptLicense encrypts license data using AES and RSA with pooled resources
func encryptLicense(data []byte) (string, error) {
	// Get pooled AES key and IV
	key := aesKeyPool.Get().([]byte)
	defer aesKeyPool.Put(key)

	iv := ivPool.Get().([]byte)
	defer ivPool.Put(iv)

	// Generate fresh random data
	if _, err := rand.Read(key); err != nil {
		log.Printf("Failed to generate AES key: %v", err)
		return "", err
	}

	if _, err := rand.Read(iv); err != nil {
		log.Printf("Failed to generate AES IV: %v", err)
		return "", err
	}

	encryptedData, err := Encrypt(data, key, iv)
	if err != nil {
		log.Printf("Failed to encrypt data: %v", err)
		return "", err
	}

	// Note: RSA encryption is typically done with a public key, but technically can be done with a private key (although not recommended)
	encryptedKey, err := encryptWithPrivateKey(string(key))
	if err != nil {
		return "", err
	}

	// Encode encrypted data as Base64
	encryptedDataStr := base64.StdEncoding.EncodeToString(encryptedData)
	ivStr := base64.StdEncoding.EncodeToString(iv)

	// Package as JSON format
	result := map[string]string{
		"data": encryptedDataStr,
		"key":  encryptedKey,
		"iv":   ivStr,
	}
	jsonData, err := json.Marshal(result)
	if err != nil {
		log.Printf("Failed to package JSON data: %v", err)
		return "", err
	}

	// Encode JSON as Base64
	encodedFinal := base64.StdEncoding.EncodeToString(jsonData)
	return encodedFinal, nil
}

// Generate generates a license and sends it via HTTP response
func Generate(ctx *gin.Context, licenseInfo entity.LicenseInfo, expireTime string) {
	createLicense(ctx, licenseInfo, expireTime)
}

// createLicense creates and sends a license. Responses are intentionally not cached:
// the payload carries a freshly randomized subscription_id / subscription_name on every
// call, so each download must be regenerated end-to-end.
func createLicense(ctx *gin.Context, licenseInfo entity.LicenseInfo, expireTime string) {
	// Create license JSON data
	licenseJson, err := createLicenseJson(licenseInfo, expireTime)
	if err != nil {
		log.Printf("Failed to create license JSON: %v", err)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// Encrypt the license data
	encryptedLicense, err := encryptLicense(licenseJson)
	if err != nil {
		log.Printf("Failed to encrypt license: %v", err)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// Create ZIP file in memory first for caching
	buf := &bytes.Buffer{}
	zipWriter := zip.NewWriter(buf)

	// Add public key file to ZIP
	if err := addFileToZipOptimized(zipWriter, config.GetConfig().DataDir+"/.license_encryption_key.pub", "license/.license_encryption_key.pub"); err != nil {
		log.Printf("Failed to add public key to ZIP: %v", err)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// Add encrypted license data to ZIP
	if err := addLicenseToZip(zipWriter, encryptedLicense, "license/license.gitlab-license"); err != nil {
		log.Printf("Failed to add license to ZIP: %v", err)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	if err := zipWriter.Close(); err != nil {
		log.Printf("Failed to close ZIP writer: %v", err)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	zipData := buf.Bytes()

	// Send response
	ctx.Header("Content-Disposition", "attachment; filename=license.zip")
	ctx.Header("Content-Type", "application/zip")
	ctx.Data(http.StatusOK, "application/zip", zipData)
}

// exportZipStream creates and sends a ZIP file containing the encrypted license and public key file
// This function is kept for backward compatibility but is no longer used in the optimized flow
func exportZipStream(ctx *gin.Context, encryptedLicense string) error {
	// Set response headers for file download
	ctx.Status(http.StatusOK) // Explicitly set status code to 200 OK
	ctx.Header("Content-Disposition", "attachment; filename=license.zip")
	ctx.Header("Content-Type", "application/zip")

	zipWriter := zip.NewWriter(ctx.Writer)
	defer func(zipWriter *zip.Writer) {
		err := zipWriter.Close()
		if err != nil {
			log.Printf("Failed to close ZIP writer: %v", err)
		}
	}(zipWriter)

	// Add public key file to ZIP
	if err := addFileToZipOptimized(zipWriter, config.GetConfig().DataDir+"/.license_encryption_key.pub", "license/.license_encryption_key.pub"); err != nil {
		return err
	}

	// Add encrypted license data to ZIP
	if err := addLicenseToZip(zipWriter, encryptedLicense, "license/license.gitlab-license"); err != nil {
		return err
	}

	return nil
}

// addFileToZipOptimized reads a file from the filesystem and adds it to the ZIP with buffered I/O
func addFileToZipOptimized(zipWriter *zip.Writer, filePath, zipPath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}

	header, err := zip.FileInfoHeader(fileInfo)
	if err != nil {
		return err
	}
	header.Name = zipPath
	header.Method = zip.Deflate
	header.Modified = fileInfo.ModTime()

	zipFile, err := zipWriter.CreateHeader(header)
	if err != nil {
		return err
	}

	// Use pooled buffer for efficient copying
	buffer := ioBufferPool.Get().([]byte)
	defer ioBufferPool.Put(buffer)

	_, err = io.CopyBuffer(zipFile, file, buffer)
	return err
}

// addLicenseToZip directly writes string data to a ZIP entry
func addLicenseToZip(zipWriter *zip.Writer, data, zipPath string) error {
	// Create a new zip.FileHeader, set filename and modification time
	header := &zip.FileHeader{
		Name:     zipPath,
		Method:   zip.Deflate, // Use compression to reduce file size
		Modified: time.Now(),  // Set current time as file modification time
	}

	// Create ZIP entry
	zipFile, err := zipWriter.CreateHeader(header)
	if err != nil {
		return err
	}

	// Write data to ZIP entry
	_, err = zipFile.Write([]byte(data))
	return err
}
