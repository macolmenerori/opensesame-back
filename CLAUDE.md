# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

- `yarn dev` - Start development server with hot reload using nodemon
- `yarn build` - Compile TypeScript to JavaScript in `dist/` directory
- `yarn start` - Start production server from compiled `dist/server.js`
- `yarn lint` - Run ESLint with auto-fix
- `yarn prettify` - Format code with Prettier
- `yarn types` - Run TypeScript type checking without emitting files
- `yarn verify` - Run full verification pipeline: audit, lint, prettify, types, and build
- `yarn gitleaks` - Run security scan using gitleaks script

## Architecture Overview

This is a Node.js/Express authentication API built with TypeScript and MongoDB.

### Core Structure
- **Entry Point**: `src/server.ts` - Handles database connection, environment setup, and server startup
- **Application**: `src/app.ts` - Express app configuration with security middleware (CORS, helmet, rate limiting, mongo sanitization)
- **Models**: `src/models/userModel.ts` - Mongoose user schema with bcrypt password hashing and JWT methods
- **Controllers**: `src/controllers/authController.ts` - Authentication logic, token management, user CRUD operations
- **Routes**: `src/routes/userRouter.ts` - API endpoints mounted at `/api/v1/users`
- **Validations**: `src/validations/userValidation.ts` - Express-validator schemas
- **Utils**: `src/utils/` - Utility functions including async error handling and environment checks

### Authentication System
- JWT-based authentication supporting both Bearer tokens and HTTP-only cookies
- Role-based access control (admin/user roles)
- Permission-based authorization system
- Bcrypt password hashing with configurable difficulty
- Password change tracking and token invalidation

### Key Features
- User registration/login/logout
- Role and permission management
- User search by name, email, or ID
- Password management (self and admin changes)
- Pagination support for user listings
- Security middleware stack (rate limiting, CORS, sanitization, compression)

### Environment Configuration
Configuration is handled via `config.env` file. Key variables include database connection, JWT settings, rate limiting, and CORS whitelist.

### API Documentation
OpenAPI specification available at `docs/openapi.yml`

### Build System
- TypeScript compilation to CommonJS
- Output to `dist/` directory
- Node.js >=22.11.0 required
- Yarn package manager