package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"io"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

type LicenseKey struct {
	ID         uint   `gorm:"primaryKey" json:"id"`
	Key        string `gorm:"uniqueIndex" json:"key"`
	ClientName string `json:"client_name"`
	Active     bool   `json:"active"`
}

func main() {
	db, err := gorm.Open(sqlite.Open("keys.db"), &gorm.Config{})
	if err != nil {
		log.Fatal("failed to connect database")
	}
	db.AutoMigrate(&LicenseKey{})

	app := fiber.New()
	app.Use(cors.New()) // Needed so Auditor can make requests to /api/verify from its own port

	// 1. Serve Admin HTML (Secure this via basic auth in real world, omitted here for simplicity)
	app.Static("/", "./admin.html")

	// 2. Public API for Auditor Clients
	app.Get("/api/verify", func(c *fiber.Ctx) error {
		providedKey := c.Query("key")
		var l LicenseKey
		if err := db.Where("key = ? AND active = ?", providedKey, true).First(&l).Error; err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"valid": false})
		}
		return c.JSON(fiber.Map{"valid": true, "client": l.ClientName})
	})

	// 3. API for Admin Dashboard (CRUD)
	app.Get("/admin/keys", func(c *fiber.Ctx) error {
		var keys []LicenseKey
		db.Find(&keys)
		return c.JSON(keys)
	})

	app.Post("/admin/keys", func(c *fiber.Ctx) error {
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

	app.Delete("/admin/keys/:id", func(c *fiber.Ctx) error {
		id := c.Params("id")
		db.Delete(&LicenseKey{}, id)
		return c.SendStatus(200)
	})

	app.Put("/admin/keys/:id/toggle", func(c *fiber.Ctx) error {
		id := c.Params("id")
		var l LicenseKey
		if err := db.First(&l, id).Error; err != nil {
			return c.SendStatus(404)
		}
		l.Active = !l.Active
		db.Save(&l)
		return c.JSON(l)
	})

	// 4. API for Decrypting AES-GCM files sent by SOC Teams
	app.Post("/admin/decrypt", func(c *fiber.Ctx) error {
		file, err := c.FormFile("payload")
		if err != nil {
			return c.Status(400).SendString("Missing payload file")
		}
		f, _ := file.Open()
		defer f.Close()
		data, _ := io.ReadAll(f)

		// Same key used in backend/main.go
		encryptionKey := []byte("NoviSec-AES-256-Key-Super-Secret")
		block, err := aes.NewCipher(encryptionKey)
		if err != nil {
			return c.Status(500).SendString("Error creating cipher")
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return c.Status(500).SendString("Error creating GCM")
		}
		nonceSize := gcm.NonceSize()
		if len(data) < nonceSize {
			return c.Status(400).SendString("Ciphertext too short")
		}
		nonce, ciphertext := data[:nonceSize], data[nonceSize:]
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
