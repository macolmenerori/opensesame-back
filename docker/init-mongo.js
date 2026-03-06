/* eslint-disable no-undef */
// SET UP MONGODB
// Switch to mongoDB admin database
db = db.getSiblingDB('admin');

// Create database admin with root privileges
db.createUser({
  user: 'admindb',
  pwd: 'admindb',
  roles: [{ role: 'root', db: 'admin' }]
});

// SET UP OPENSESAME
// Create opensesame database
db = db.getSiblingDB('opensesame');

// Create users collection
db.createCollection('users');

// Insert default user. user: admin@admin.com, password: administrator
db.users.insertOne({
  name: 'Admin',
  email: 'admin@admin.com',
  role: 'admin',
  password: '$2b$12$GhCoggnxkqF1WtU/KIxmjuouaMexO4cZBbkP8mzVWCnq56mqqcQfG',
  passwordChangedAt: new Date(),
  permissions: []
});
