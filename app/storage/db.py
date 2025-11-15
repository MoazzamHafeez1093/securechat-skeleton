"""MySQL users table + salted hashing (no chat storage)."""
import os
import hashlib
import secrets
from typing import Optional, Tuple
import pymysql
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class UserDB:
    """Handles MySQL connection and user credential management."""
    
    def __init__(self):
        """Initialize database connection from environment variables."""
        self.host = os.getenv("DB_HOST", "localhost")
        self.user = os.getenv("DB_USER", "root")
        self.password = os.getenv("DB_PASSWORD")
        self.database = os.getenv("DB_NAME", "securechat")
        self.connection = None
    
    def connect(self) -> None:
        """Establish connection to MySQL database."""
        try:
            self.connection = pymysql.connect(
                host=self.host,
                user=self.user,
                password=self.password,
                database=self.database,
                charset='utf8mb4',
                cursorclass=pymysql.cursors.DictCursor
            )
        except pymysql.Error as e:
            raise RuntimeError(f"Failed to connect to MySQL: {e}")
    
    def disconnect(self) -> None:
        """Close database connection."""
        if self.connection:
            self.connection.close()
            self.connection = None
    
    def __enter__(self):
        """Context manager entry - establish connection."""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - close connection."""
        self.disconnect()
    
    @staticmethod
    def generate_salt() -> bytes:
        """Generate a cryptographically secure 16-byte random salt."""
        return secrets.token_bytes(16)
    
    @staticmethod
    def hash_password(password: str, salt: bytes) -> str:
        """
        Compute salted SHA-256 hash of password.
        
        Args:
            password: plaintext password
            salt: 16-byte random salt
            
        Returns:
            Hex-encoded SHA-256 hash of (salt || password)
        """
        # Concatenate salt and password, then hash
        combined = salt + password.encode('utf-8')
        pwd_hash = hashlib.sha256(combined).hexdigest()
        return pwd_hash
    
    def register_user(self, email: str, username: str, password: str) -> bool:
        """
        Register a new user with salted password hash.
        
        Args:
            email: user email address
            username: unique username
            password: plaintext password (will be hashed)
            
        Returns:
            True if registration successful, False if user already exists
            
        Raises:
            RuntimeError: if database operation fails
        """
        if not self.connection:
            raise RuntimeError("Not connected to database")
        
        # Generate random salt
        salt = self.generate_salt()
        
        # Compute salted hash
        pwd_hash = self.hash_password(password, salt)
        
        try:
            with self.connection.cursor() as cursor:
                # Check if user already exists
                cursor.execute(
                    "SELECT id FROM users WHERE email = %s OR username = %s",
                    (email, username)
                )
                if cursor.fetchone():
                    return False  # User already exists
                
                # Insert new user
                cursor.execute(
                    """
                    INSERT INTO users (email, username, salt, pwd_hash)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (email, username, salt, pwd_hash)
                )
                self.connection.commit()
                return True
        except pymysql.Error as e:
            self.connection.rollback()
            raise RuntimeError(f"Failed to register user: {e}")
    
    def verify_login(self, email: str, password: str) -> Tuple[bool, Optional[str]]:
        """
        Verify user credentials during login.
        
        Args:
            email: user email address
            password: plaintext password to verify
            
        Returns:
            Tuple of (success: bool, username: Optional[str])
            - (True, username) if credentials valid
            - (False, None) if credentials invalid or user not found
            
        Raises:
            RuntimeError: if database operation fails
        """
        if not self.connection:
            raise RuntimeError("Not connected to database")
        
        try:
            with self.connection.cursor() as cursor:
                # Fetch user record
                cursor.execute(
                    "SELECT username, salt, pwd_hash FROM users WHERE email = %s",
                    (email,)
                )
                result = cursor.fetchone()
                
                if not result:
                    return False, None  # User not found
                
                username = result['username']
                salt = result['salt']
                stored_hash = result['pwd_hash']
                
                # Recompute hash with provided password
                computed_hash = self.hash_password(password, salt)
                
                # Constant-time comparison to prevent timing attacks
                if secrets.compare_digest(computed_hash, stored_hash):
                    return True, username
                else:
                    return False, None
        except pymysql.Error as e:
            raise RuntimeError(f"Failed to verify login: {e}")
    
    def user_exists(self, email: str) -> bool:
        """
        Check if a user with given email exists.
        
        Args:
            email: user email address
            
        Returns:
            True if user exists, False otherwise
        """
        if not self.connection:
            raise RuntimeError("Not connected to database")
        
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
                return cursor.fetchone() is not None
        except pymysql.Error as e:
            raise RuntimeError(f"Failed to check user existence: {e}")


def main():
    """Test database operations (for development/testing only)."""
    print("Testing SecureChat Database Layer")
    print("-" * 50)
    
    try:
        with UserDB() as db:
            print("✓ Connected to MySQL database")
            
            # Test registration
            test_email = "test@example.com"
            test_username = "testuser"
            test_password = "TestPass123!"
            
            print(f"\nTesting registration for {test_email}...")
            success = db.register_user(test_email, test_username, test_password)
            if success:
                print("✓ User registered successfully")
            else:
                print("⚠ User already exists")
            
            # Test login with correct password
            print(f"\nTesting login with correct password...")
            success, username = db.verify_login(test_email, test_password)
            if success:
                print(f"✓ Login successful, username: {username}")
            else:
                print("✗ Login failed")
            
            # Test login with wrong password
            print(f"\nTesting login with wrong password...")
            success, username = db.verify_login(test_email, "WrongPassword")
            if not success:
                print("✓ Login correctly rejected")
            else:
                print("✗ Security issue: accepted wrong password!")
            
            print("\n" + "-" * 50)
            print("Database layer tests completed")
    
    except Exception as e:
        print(f"✗ Error: {e}")


if __name__ == "__main__":
    main()
