package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/glebarez/sqlite"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/basicauth"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"gorm.io/gorm"
)

type LicenseKey struct {
	ID         uint   `gorm:"primaryKey" json:"id"`
	Key        string `gorm:"uniqueIndex" json:"key"`
	ClientName string `json:"client_name"`
	Active     bool   `json:"active"`
}

func main() {
	if err := os.MkdirAll("data", 0755); err != nil {
		log.Fatalf("failed to create data directory: %v", err)
	}

	db, err := gorm.Open(sqlite.Open("data/keys.db"), &gorm.Config{})
	if err != nil {
		log.Fatalf("failed to connect database: %v", err)
	}
	db.AutoMigrate(&LicenseKey{})

	app := fiber.New()
	app.Use(cors.New()) // Needed so Auditor can make requests to /api/verify from its own port

	// Read credentials from env vars (with secure defaults for local dev)
	adminUser := os.Getenv("ADMIN_USER")
	if adminUser == "" {
		adminUser = "novisec"
	}
	adminPass := os.Getenv("ADMIN_PASS")
	if adminPass == "" {
		adminPass = "NoviSec@SOC2025!"
	}

	auth := basicauth.New(basicauth.Config{
		Users: map[string]string{
			adminUser: adminPass,
		},
		Realm: "NoviSec Admin Panel",
		Unauthorized: func(c *fiber.Ctx) error {
			c.Set("WWW-Authenticate", `Basic realm="NoviSec Admin Panel"`)
			return c.Status(fiber.StatusUnauthorized).SendString("401 Unauthorized — NoviSec Admin Panel")
		},
	})

	// 1. Serve Admin HTML — protected by Basic Auth
	app.Get("/", auth, func(c *fiber.Ctx) error {
		return c.SendFile("./admin.html")
	})

	// 2. Public API for Auditor Clients
	app.Get("/api/verify", func(c *fiber.Ctx) error {
		providedKey := c.Query("key")
		var l LicenseKey
		if err := db.Where("key = ? AND active = ?", providedKey, true).First(&l).Error; err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"valid": false})
		}
		return c.JSON(fiber.Map{"valid": true, "client": l.ClientName})
	})

	// 3. API for Admin Dashboard (CRUD) — all protected
	app.Get("/admin/keys", auth, func(c *fiber.Ctx) error {
		var keys []LicenseKey
		db.Find(&keys)
		return c.JSON(keys)
	})

	app.Post("/admin/keys", auth, func(c *fiber.Ctx) error {
		var req LicenseKey
		if err := c.BodyParser(&req); err != nil {
			return c.Status(400).SendString(err.Error())
		}
		req.Active = true
		if res := db.Create(&req); res.Error != nil {
			return c.Status(400).SendString("Key already exists or invalid")
		}
		return c.JSON(req)
	})

	app.Delete("/admin/keys/:id", auth, func(c *fiber.Ctx) error {
		id := c.Params("id")
		db.Delete(&LicenseKey{}, id)
		return c.SendStatus(200)
	})

	app.Put("/admin/keys/:id/toggle", auth, func(c *fiber.Ctx) error {
		id := c.Params("id")
		var l LicenseKey
		if err := db.First(&l, id).Error; err != nil {
			return c.SendStatus(404)
		}
		l.Active = !l.Active
		db.Save(&l)
		return c.JSON(l)
	})

	// 4. API for Decrypting AES-GCM files sent by SOC Teams — protected
	app.Post("/admin/decrypt", auth, func(c *fiber.Ctx) error {
		file, err := c.FormFile("payload")
		if err != nil {
			return c.Status(400).SendString("Missing payload file")
		}
		f, _ := file.Open()
		defer f.Close()
		data, _ := io.ReadAll(f)

		// Parse the JSON file
		var report map[string]interface{}
		if err := json.Unmarshal(data, &report); err != nil {
			return c.Status(400).SendString("Failed to parse JSON file")
		}

		encryptedHex, ok := report["encrypted_payload"].(string)
		if !ok {
			return c.Status(400).SendString("Missing 'encrypted_payload' in JSON")
		}

		// Decode hex to raw bytes
		raw, err := hex.DecodeString(encryptedHex)
		if err != nil {
			return c.Status(400).SendString("Invalid hex payload")
		}

		// Same key used in backend/main.go
		encryptionKey := []byte("$zd#9UHTqYLX05OIzzLIdbe%l><^kIAT")
		block, err := aes.NewCipher(encryptionKey)
		if err != nil {
			return c.Status(500).SendString("Error creating cipher")
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return c.Status(500).SendString("Error creating GCM")
		}
		nonceSize := gcm.NonceSize()
		if len(raw) < nonceSize {
			return c.Status(400).SendString("Ciphertext too short")
		}
		nonce, ciphertext := raw[:nonceSize], raw[nonceSize:]
		plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return c.Status(400).SendString(fmt.Sprintf("Failed to decrypt: %v (Wrong key?)", err))
		}

		// Send decypted JSON back to be displayed by HTML
		var payload map[string]interface{}
		json.Unmarshal(plaintext, &payload)
		return c.JSON(payload)
	})

	log.Println("✅ NoviSec Admin Server running on http://127.0.0.1:9000")
	log.Fatal(app.Listen(":9000"))
}
