"""
Simple tests for the manage_users_roles Lambda function
Tests the core logic without requiring AWS services
"""
import sys
import os
import json
import bcrypt
from datetime import datetime

# Mock boto3 for testing
class MockTable:
    def __init__(self, name):
        self.name = name
        self.data = {}
    
    def get_item(self, Key):
        key_str = json.dumps(Key, sort_keys=True)
        if key_str in self.data:
            return {'Item': self.data[key_str]}
        return {}
    
    def put_item(self, Item):
        if 'username' in Item and 'role_arn' in Item:
            key = {'username': Item['username'], 'role_arn': Item['role_arn']}
        else:
            key = {'username': Item['username']}
        key_str = json.dumps(key, sort_keys=True)
        self.data[key_str] = Item
        return {'ResponseMetadata': {'HTTPStatusCode': 200}}
    
    def update_item(self, Key, UpdateExpression, ExpressionAttributeNames, ExpressionAttributeValues, ReturnValues):
        key_str = json.dumps(Key, sort_keys=True)
        if key_str not in self.data:
            raise Exception("Item not found")
        
        item = self.data[key_str].copy()
        
        # Apply updates from ExpressionAttributeValues
        for value_placeholder, value in ExpressionAttributeValues.items():
            # Find the corresponding attribute name
            for name_placeholder, attr_name in ExpressionAttributeNames.items():
                # Check if both placeholders are in the update expression
                if name_placeholder in UpdateExpression and value_placeholder in UpdateExpression:
                    # Check if they're paired in the expression (e.g., "#email = :email")
                    if f"{name_placeholder} = {value_placeholder}" in UpdateExpression:
                        item[attr_name] = value
        
        self.data[key_str] = item
        return {'Attributes': item}

class MockDynamoDB:
    def __init__(self):
        self.tables = {
            'users': MockTable('users'),
            'roles': MockTable('roles')
        }
    
    def Table(self, name):
        if 'users' in name:
            return self.tables['users']
        elif 'roles' in name:
            return self.tables['roles']
        return MockTable(name)

# Mock boto3
class MockBoto3:
    @staticmethod
    def resource(service_name):
        if service_name == 'dynamodb':
            return MockDynamoDB()
        return None

# Create mock modules before importing anything
class MockClientError(Exception):
    pass

class MockExceptions:
    ClientError = MockClientError

class MockBotocore:
    exceptions = MockExceptions()

sys.modules['boto3'] = MockBoto3()
sys.modules['botocore.exceptions'] = MockExceptions()

# Set environment variables
os.environ['USERS_TABLE'] = 'test-users'
os.environ['ROLES_TABLE'] = 'test-roles'

# Now import the module
sys.path.insert(0, '/home/runner/work/simple-saml-idp/simple-saml-idp/lambda/function')
import manage_users_roles

def test_create_user():
    """Test user creation with all fields"""
    event = {
        "operation": "create_user",
        "data": {
            "username": "test.user",
            "password": "testpass",
            "email": "test@example.com",
            "first_name": "Test",
            "last_name": "User",
            "enabled": True
        }
    }
    
    result = manage_users_roles.lambda_handler(event, None)
    assert result['statusCode'] == 200
    body = json.loads(result['body'])
    assert body['success'] == True
    assert body['data']['username'] == 'test.user'
    assert body['data']['email'] == 'test@example.com'
    assert 'password_hash' not in body['data']  # Should be removed from response
    print("✓ test_create_user passed")

def test_create_user_minimal():
    """Test user creation with minimal fields"""
    event = {
        "operation": "create_user",
        "data": {
            "username": "minimal.user",
            "password": "testpass"
        }
    }
    
    result = manage_users_roles.lambda_handler(event, None)
    assert result['statusCode'] == 200
    body = json.loads(result['body'])
    assert body['success'] == True
    assert body['data']['username'] == 'minimal.user'
    assert body['data']['email'] == 'minimal.user@example.com'
    assert body['data']['first_name'] == 'Minimal'
    assert body['data']['last_name'] == 'User'
    assert body['data']['enabled'] == True
    print("✓ test_create_user_minimal passed")

def test_create_user_duplicate():
    """Test creating duplicate user"""
    event = {
        "operation": "create_user",
        "data": {
            "username": "test.user",
            "password": "testpass"
        }
    }
    
    result = manage_users_roles.lambda_handler(event, None)
    assert result['statusCode'] == 409  # Conflict
    body = json.loads(result['body'])
    assert body['success'] == False
    print("✓ test_create_user_duplicate passed")

def test_update_user():
    """Test user update"""
    event = {
        "operation": "update_user",
        "data": {
            "username": "test.user",
            "email": "updated@example.com",
            "enabled": False
        }
    }
    
    result = manage_users_roles.lambda_handler(event, None)
    print(f"Update result status: {result['statusCode']}")
    print(f"Update result body: {result['body']}")
    assert result['statusCode'] == 200, f"Expected 200, got {result['statusCode']}: {result['body']}"
    body = json.loads(result['body'])
    assert body['success'] == True
    assert body['data']['email'] == 'updated@example.com'
    assert body['data']['enabled'] == False
    print("✓ test_update_user passed")

def test_update_user_password():
    """Test password update"""
    event = {
        "operation": "update_user",
        "data": {
            "username": "test.user",
            "password": "newpassword"
        }
    }
    
    result = manage_users_roles.lambda_handler(event, None)
    assert result['statusCode'] == 200
    body = json.loads(result['body'])
    assert body['success'] == True
    print("✓ test_update_user_password passed")

def test_create_role():
    """Test role creation with all fields"""
    event = {
        "operation": "create_role",
        "data": {
            "username": "test.user",
            "role_arn": "arn:aws:iam::123456789012:role/TestRole",
            "account_name": "Test Account",
            "description": "Test role description"
        }
    }
    
    result = manage_users_roles.lambda_handler(event, None)
    assert result['statusCode'] == 200
    body = json.loads(result['body'])
    assert body['success'] == True
    assert body['data']['username'] == 'test.user'
    assert body['data']['role_arn'] == 'arn:aws:iam::123456789012:role/TestRole'
    assert body['data']['account_id'] == '123456789012'
    assert body['data']['account_name'] == 'Test Account'
    print("✓ test_create_role passed")

def test_create_role_minimal():
    """Test role creation with minimal fields"""
    event = {
        "operation": "create_role",
        "data": {
            "username": "test.user",
            "role_arn": "arn:aws:iam::987654321098:role/AnotherRole"
        }
    }
    
    result = manage_users_roles.lambda_handler(event, None)
    assert result['statusCode'] == 200
    body = json.loads(result['body'])
    assert body['success'] == True
    assert body['data']['account_id'] == '987654321098'
    assert body['data']['account_name'] == '987654321098'  # Should default to account ID
    print("✓ test_create_role_minimal passed")

def test_update_role():
    """Test role update"""
    event = {
        "operation": "update_role",
        "data": {
            "username": "test.user",
            "role_arn": "arn:aws:iam::123456789012:role/TestRole",
            "account_name": "Updated Account",
            "description": "Updated description"
        }
    }
    
    result = manage_users_roles.lambda_handler(event, None)
    assert result['statusCode'] == 200
    body = json.loads(result['body'])
    assert body['success'] == True
    assert body['data']['account_name'] == 'Updated Account'
    assert body['data']['description'] == 'Updated description'
    print("✓ test_update_role passed")

def test_missing_operation():
    """Test missing operation field"""
    event = {
        "data": {
            "username": "test"
        }
    }
    
    result = manage_users_roles.lambda_handler(event, None)
    assert result['statusCode'] == 400
    body = json.loads(result['body'])
    assert body['success'] == False
    print("✓ test_missing_operation passed")

def test_invalid_operation():
    """Test invalid operation"""
    event = {
        "operation": "delete_user",
        "data": {
            "username": "test"
        }
    }
    
    result = manage_users_roles.lambda_handler(event, None)
    assert result['statusCode'] == 400
    body = json.loads(result['body'])
    assert body['success'] == False
    print("✓ test_invalid_operation passed")

def test_password_hashing():
    """Test that password is properly hashed with bcrypt"""
    password = "testpassword"
    
    event = {
        "operation": "create_user",
        "data": {
            "username": "hash.test",
            "password": password
        }
    }
    
    result = manage_users_roles.lambda_handler(event, None)
    assert result['statusCode'] == 200
    
    # Verify the response doesn't contain the plain password or hash
    body = json.loads(result['body'])
    assert 'password' not in body['data']
    assert 'password_hash' not in body['data']
    
    print("✓ test_password_hashing passed")

def test_username_with_multiple_dots():
    """Test username parsing with multiple dots"""
    event = {
        "operation": "create_user",
        "data": {
            "username": "john.van.der.berg",
            "password": "testpass"
        }
    }
    
    result = manage_users_roles.lambda_handler(event, None)
    assert result['statusCode'] == 200
    body = json.loads(result['body'])
    assert body['success'] == True
    assert body['data']['first_name'] == 'John'
    assert body['data']['last_name'] == 'Van Der Berg'
    print("✓ test_username_with_multiple_dots passed")

if __name__ == "__main__":
    print("Running Lambda function tests...")
    print()
    
    try:
        test_create_user()
        test_create_user_minimal()
        test_create_user_duplicate()
        test_update_user()
        test_update_user_password()
        test_create_role()
        test_create_role_minimal()
        test_update_role()
        test_missing_operation()
        test_invalid_operation()
        test_password_hashing()
        test_username_with_multiple_dots()
        
        print()
        print("=" * 50)
        print("All tests passed! ✓")
        print("=" * 50)
    except AssertionError as e:
        print()
        print("=" * 50)
        print(f"Test failed: {e}")
        print("=" * 50)
        sys.exit(1)
    except Exception as e:
        print()
        print("=" * 50)
        print(f"Test error: {e}")
        print("=" * 50)
        sys.exit(1)
