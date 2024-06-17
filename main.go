package main

import (
	"database/sql"

	"encoding/json"
	"fmt"

	"log"
	"net/http"
	"sync"

	"errors"
	"regexp"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
)

// Define a global variable to hold the database connection.
var db *sql.DB

type User struct {
	ID       uuid.UUID `json:"id"`
	Email    string    `json:"email"`
	Password string    `json:"password"`
	Deposit  int       `json:"deposit"`
	Role     string    `json:"role"` // "seller" or "buyer"
}

type Product struct {
	ID              uuid.UUID `json:"id"`
	ProductName     string    `json:"productName"`
	Cost            float64   `json:"cost"` // Updated to float64 to handle decimals
	AmountAvailable int       `json:"amountAvailable"`
	SellerEmail     string    `json:"sellerEmail"`
}

type ErrorResponse struct {
	ErrorCode    string `json:"errorCode"`
	ErrorMessage string `json:"errorMessage"`
	Field        string `json:"field,omitempty"`
}

var (
	users     = make(map[string]User) // Key is now email
	userMutex = &sync.Mutex{}
)

var (
	products     = make(map[string]Product) // Key is ProductName
	productMutex = &sync.Mutex{}
)

var validCoins = map[int]bool{
	5:   true,
	10:  true,
	20:  true,
	50:  true,
	100: true,
}

func main() {

	// Connect to the database
	var err error
	db, err = connectDB()
	if err != nil {
		log.Fatalf("Error connecting to the database: %s", err)
	}
	defer db.Close()

	router := mux.NewRouter()

	// Setup your routes here
	router.HandleFunc("/users", createUserHandler).Methods("POST")
	router.HandleFunc("/users", getAllUser).Methods("GET")
	router.HandleFunc("/users/{email}", getUser).Methods("GET")
	router.HandleFunc("/users/{email}", updateUser).Methods("PUT")
	router.HandleFunc("/users/{email}", deleteUser).Methods("DELETE")

	// Product endpoints for postgres
	router.HandleFunc("/products", createProduct).Methods("POST")
	router.HandleFunc("/products", getAllProducts).Methods("GET")
	router.HandleFunc("/products/{productName}", getProduct).Methods("GET")
	router.HandleFunc("/products/{productName}", updateProduct).Methods("PUT")
	router.HandleFunc("/products/{productName}", deleteProduct).Methods("DELETE")

	// Buy product endpoint
	router.HandleFunc("/buy", buyProductHandler).Methods("POST")

	// Deposit coins endpoint
	router.HandleFunc("/deposit", depositCoinsHandler).Methods("POST")

	// Reset deposit endpoint
	router.HandleFunc("/reset", resetDepositHandler).Methods("POST")

	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", router))

}
func connectDB() (*sql.DB, error) {
	// Connect to the database
	const (
		host     = "localhost"
		port     = 5432
		user     = "postgres"
		password = "12345678"
		dbname   = "vending"
	)
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}

	err = db.Ping()
	if err != nil {
		return nil, err
	}

	log.Println("Successfully connected to the database")
	return db, nil
}

// createUserHandler creates a new user.
func createUserHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user.ID = uuid.New()
	sqlStatement := `INSERT INTO users (id, email, password, deposit, role) VALUES ($1, $2, $3, $4, $5)`
	_, err := db.Exec(sqlStatement, user.ID, user.Email, user.Password, user.Deposit, user.Role)
	if err != nil {
		http.Error(w, "Failed to create user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
}

// getAllUser retrieves all users.
func getAllUser(w http.ResponseWriter, r *http.Request) {
	users := []User{}
	sqlStatement := `SELECT id, email, password, deposit, role FROM users`
	rows, err := db.Query(sqlStatement)
	if err != nil {
		http.Error(w, "Failed to retrieve users: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Email, &user.Password, &user.Deposit, &user.Role)
		if err != nil {
			http.Error(w, "Failed to scan user: "+err.Error(), http.StatusInternalServerError)
			return
		}
		users = append(users, user)
	}

	json.NewEncoder(w).Encode(users)
}

// getUser retrieves a user by email
func getUser(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	email := params["email"]
	user := User{}

	sqlStatement := `SELECT id, email, password, deposit, role FROM users WHERE email = $1`
	row := db.QueryRow(sqlStatement, email)
	err := row.Scan(&user.ID, &user.Email, &user.Password, &user.Deposit, &user.Role)
	if err != nil {
		if err == sql.ErrNoRows {
			http.NotFound(w, r)
		} else {
			http.Error(w, "Failed to retrieve user: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	json.NewEncoder(w).Encode(user)
}

// updateUser updates a user's information
func updateUser(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	email := params["email"]
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	sqlStatement := `UPDATE users SET password = $1, deposit = $2, role = $3 WHERE email = $4`
	_, err := db.Exec(sqlStatement, user.Password, user.Deposit, user.Role, email)
	if err != nil {
		http.Error(w, "Failed to update user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// deleteUser deletes a user
func deleteUser(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	email := params["email"]

	sqlStatement := `DELETE FROM users WHERE email = $1`
	_, err := db.Exec(sqlStatement, email)
	if err != nil {
		http.Error(w, "Failed to delete user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// createProduct creates a new product
func createProduct(w http.ResponseWriter, r *http.Request) {
	var product Product
	if err := json.NewDecoder(r.Body).Decode(&product); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check if seller exists
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)", product.SellerEmail).Scan(&exists)
	if err != nil {
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !exists {
		http.Error(w, "Seller does not exist", http.StatusBadRequest)
		return
	}

	product.ID = uuid.New()
	sqlStatement := `INSERT INTO products (id, product_name, cost, amount_available, seller_email) VALUES ($1, $2, $3, $4, $5)`
	_, err = db.Exec(sqlStatement, product.ID, product.ProductName, product.Cost, product.AmountAvailable, product.SellerEmail)
	if err != nil {
		http.Error(w, "Failed to create product: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(product)
}

// getAllProducts retrieves all products
func getAllProducts(w http.ResponseWriter, r *http.Request) {
	products := []Product{}
	sqlStatement := `SELECT id, product_name, cost, amount_available, seller_email FROM products`
	rows, err := db.Query(sqlStatement)
	if err != nil {
		http.Error(w, "Failed to retrieve products: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var product Product
		err := rows.Scan(&product.ID, &product.ProductName, &product.Cost, &product.AmountAvailable, &product.SellerEmail)
		if err != nil {
			http.Error(w, "Failed to scan product: "+err.Error(), http.StatusInternalServerError)
			return
		}
		products = append(products, product)
	}

	json.NewEncoder(w).Encode(products)
}

// getProduct retrieves a product by name
func getProduct(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	productName := params["productName"]
	product := Product{}

	sqlStatement := `SELECT id, product_name, cost, amount_available, seller_email FROM products WHERE product_name = $1`
	row := db.QueryRow(sqlStatement, productName)
	err := row.Scan(&product.ID, &product.ProductName, &product.Cost, &product.AmountAvailable, &product.SellerEmail)
	if err != nil {
		if err == sql.ErrNoRows {
			http.NotFound(w, r)
		} else {
			http.Error(w, "Failed to retrieve product: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	json.NewEncoder(w).Encode(product)
}

// updateProduct updates a product's information
func updateProduct(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	productName := params["productName"]
	var product Product
	if err := json.NewDecoder(r.Body).Decode(&product); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	sqlStatement := `UPDATE products SET cost = $1, amount_available = $2 WHERE product_name = $3 AND seller_email = $4`
	_, err := db.Exec(sqlStatement, product.Cost, product.AmountAvailable, productName, product.SellerEmail)
	if err != nil {
		http.Error(w, "Failed to update product: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// deleteProduct deletes a product
func deleteProduct(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	productName := params["productName"]
	sellerEmail := r.Header.Get("User-Email") // Assume authentication

	// Verify the seller
	var seller Product
	sqlStatement := `SELECT seller_email FROM products WHERE product_name = $1`
	row := db.QueryRow(sqlStatement, productName)
	err := row.Scan(&seller.SellerEmail)
	if err != nil {
		if err == sql.ErrNoRows {
			http.NotFound(w, r)
			return
		} else {
			http.Error(w, "Failed to find product: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	if seller.SellerEmail != sellerEmail {
		http.Error(w, "Unauthorized to delete this product", http.StatusUnauthorized)
		return
	}

	sqlStatement = `DELETE FROM products WHERE product_name = $1`
	_, err = db.Exec(sqlStatement, productName)
	if err != nil {
		http.Error(w, "Failed to delete product: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// buyProduct handles buying a product
func buyProduct(w http.ResponseWriter, r *http.Request) {
	var purchase struct {
		Email       string `json:"email"`
		ProductName string `json:"productName"`
		Quantity    int    `json:"quantity"`
	}
	if err := json.NewDecoder(r.Body).Decode(&purchase); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Transaction start
	tx, err := db.Begin()
	if err != nil {
		http.Error(w, "Failed to start transaction: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Check user exists and is a buyer
	var user User
	sqlStatement := `SELECT deposit, role FROM users WHERE email = $1`
	err = tx.QueryRow(sqlStatement, purchase.Email).Scan(&user.Deposit, &user.Role)
	if err != nil {
		tx.Rollback()
		if err == sql.ErrNoRows {
			http.NotFound(w, r)
		} else {
			http.Error(w, "User query failed: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	if user.Role != "buyer" {
		tx.Rollback()
		http.Error(w, "Unauthorized access: only buyers can purchase", http.StatusUnauthorized)
		return
	}

	// Check product exists and stock is sufficient
	var product Product
	sqlStatement = `SELECT id, cost, amount_available FROM products WHERE product_name = $1`
	err = tx.QueryRow(sqlStatement, purchase.ProductName).Scan(&product.ID, &product.Cost, &product.AmountAvailable)
	if err != nil {
		tx.Rollback()
		if err == sql.ErrNoRows {
			http.NotFound(w, r)
		} else {
			http.Error(w, "Product query failed: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	if product.AmountAvailable < purchase.Quantity {
		tx.Rollback()
		http.Error(w, "Insufficient product stock", http.StatusBadRequest)
		return
	}

	totalCost := product.Cost * float64(purchase.Quantity)
	if float64(user.Deposit) < totalCost {
		tx.Rollback()
		http.Error(w, "Insufficient funds", http.StatusBadRequest)
		return
	}

	// Update product stock
	sqlStatement = `UPDATE products SET amount_available = amount_available - $1 WHERE product_name = $2`
	_, err = tx.Exec(sqlStatement, purchase.Quantity, purchase.ProductName)
	if err != nil {
		tx.Rollback()
		http.Error(w, "Failed to update product stock: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Update user deposit
	sqlStatement = `UPDATE users SET deposit = deposit - $1 WHERE email = $2`
	_, err = tx.Exec(sqlStatement, int(totalCost), purchase.Email)
	if err != nil {
		tx.Rollback()
		http.Error(w, "Failed to update user deposit: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Commit transaction
	err = tx.Commit()
	if err != nil {
		http.Error(w, "Transaction commit failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Confirm the purchase
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":  "Purchase successful",
		"product":  purchase.ProductName,
		"quantity": purchase.Quantity,
		"spent":    totalCost,
		"balance":  user.Deposit - int(totalCost),
	})
}

// buyProductHandler handles the buying of a product by a user.
func buyProductHandler(w http.ResponseWriter, r *http.Request) {
	var purchase struct {
		Email       string `json:"email"`
		ProductName string `json:"productName"`
		Quantity    int    `json:"quantity"`
	}
	if err := json.NewDecoder(r.Body).Decode(&purchase); err != nil {
		http.Error(w, "Invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Start transaction
	tx, err := db.Begin()
	if err != nil {
		http.Error(w, "Transaction start failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	// Check user balance and role
	var deposit int
	var role string
	err = tx.QueryRow(`SELECT deposit, role FROM users WHERE email = $1`, purchase.Email).Scan(&deposit, &role)
	if err != nil {
		http.Error(w, "User not found or query failed: "+err.Error(), http.StatusNotFound)
		return
	}

	if role != "buyer" {
		http.Error(w, "Unauthorized action: Only buyers can make purchases", http.StatusUnauthorized)
		return
	}

	// Check product availability and cost
	var cost float64
	var available int
	err = tx.QueryRow(`SELECT cost, amount_available FROM products WHERE product_name = $1`, purchase.ProductName).Scan(&cost, &available)
	if err != nil {
		http.Error(w, "Product not found or query failed: "+err.Error(), http.StatusNotFound)
		return
	}

	if available < purchase.Quantity {
		http.Error(w, "Insufficient stock", http.StatusConflict)
		return
	}

	totalCost := cost * float64(purchase.Quantity)
	if float64(deposit) < totalCost {
		http.Error(w, "Insufficient funds", http.StatusBadRequest)
		return
	}

	// Update product stock
	_, err = tx.Exec(`UPDATE products SET amount_available = amount_available - $1 WHERE product_name = $2`, purchase.Quantity, purchase.ProductName)
	if err != nil {
		http.Error(w, "Failed to update product stock: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Update user deposit
	_, err = tx.Exec(`UPDATE users SET deposit = deposit - $1 WHERE email = $2`, int(totalCost), purchase.Email)
	if err != nil {
		http.Error(w, "Failed to update user deposit: "+err.Error(), http.StatusInternalServerError)
		return
	}

	err = tx.Commit()
	if err != nil {
		http.Error(w, "Transaction commit failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":  "Purchase successful",
		"product":  purchase.ProductName,
		"quantity": purchase.Quantity,
		"spent":    totalCost,
		"balance":  deposit - int(totalCost),
	})
}

// depositCoinsHandler handles the deposit of coins by a user.
func depositCoinsHandler(w http.ResponseWriter, r *http.Request) {
	var depositRequest struct {
		Email string `json:"email"`
		Coin  int    `json:"coin"`
	}
	if err := json.NewDecoder(r.Body).Decode(&depositRequest); err != nil {
		http.Error(w, "Invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}

	if !validCoins[depositRequest.Coin] {
		http.Error(w, "Invalid coin denomination", http.StatusBadRequest)
		return
	}

	_, err := db.Exec(`UPDATE users SET deposit = deposit + $1 WHERE email = $2`, depositRequest.Coin, depositRequest.Email)
	if err != nil {
		http.Error(w, "Failed to deposit coins: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Deposit successful"})
}

// resetDepositHandler handles the resetting of a user's deposit to zero.
func resetDepositHandler(w http.ResponseWriter, r *http.Request) {
	var resetRequest struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&resetRequest); err != nil {
		http.Error(w, "Invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}

	_, err := db.Exec(`UPDATE users SET deposit = 0 WHERE email = $1`, resetRequest.Email)
	if err != nil {
		http.Error(w, "Failed to reset deposit: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Deposit reset successful"})
}

// validatePassword checks if the provided password meets the defined criteria.
func validatePassword(password string) error {
	var (
		minLen  = 8
		upper   = `[A-Z]`      // Checks for uppercase letters
		lower   = `[a-z]`      // Checks for lowercase letters
		number  = `[0-9]`      // Checks for digits
		special = `[!@#$%^&*]` // Checks for special characters
	)

	if len(password) < minLen {
		return errors.New("password must be at least 8 characters long")
	}
	if match, _ := regexp.MatchString(upper, password); !match {
		return errors.New("password must include at least one uppercase letter")
	}
	if match, _ := regexp.MatchString(lower, password); !match {
		return errors.New("password must include at least one lowercase letter")
	}
	if match, _ := regexp.MatchString(number, password); !match {
		return errors.New("password must include at least one digit")
	}
	if match, _ := regexp.MatchString(special, password); !match {
		return errors.New("password must include at least one special character")
	}
	return nil
}
