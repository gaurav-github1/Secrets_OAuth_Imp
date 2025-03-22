# Authentication System

A secure user authentication system built with Node.js, Express, and PostgreSQL. This application supports both local authentication and Google OAuth.

## Features

- User registration and login with email/password
- Google OAuth integration
- Session management with PostgreSQL
- Secure password hashing with bcrypt
- User secrets management
- Responsive design

## Tech Stack

- **Backend**: Node.js with Express.js
- **Database**: PostgreSQL
- **Authentication**: Passport.js with Local and Google strategies
- **Session Management**: express-session with connect-pg-simple
- **Password Hashing**: bcrypt
- **Environment Variables**: dotenv

## Setup and Installation

### Prerequisites

- Node.js (14.x or higher)
- PostgreSQL database
- Google OAuth credentials (for Google login)

### Environment Variables

Create a `.env` file in the root directory with the following variables:

```
PORT=3000
DATABASE_URL=postgresql://username:password@localhost:5432/authdb
SESSION_SECRET=your_session_secret
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_CALLBACK_URL=http://localhost:3000/auth/google/secrets
```

### Installation Steps

1. Clone the repository
   ```
   git clone <repository-url>
   cd authentication-system
   ```

2. Install dependencies
   ```
   npm install
   ```

3. Set up the PostgreSQL database
   The application will automatically create the necessary tables on startup.

4. Start the server
   ```
   npm start
   ```

5. Access the application
   Open your browser and navigate to `http://localhost:3000`

## Application Structure

- **Routes**:
  - `/` - Home page
  - `/login` - User login
  - `/register` - New user registration
  - `/secrets` - Protected route displaying user secrets
  - `/submit` - Add or update user secret
  - `/auth/google` - Google OAuth authentication
  - `/logout` - User logout

## Security Features

- Passwords are hashed using bcrypt
- Session data is stored securely in PostgreSQL
- OAuth2 authentication with Google
- Protected routes using Passport.js middleware

## Development

For development purposes, you can run the server with nodemon:
```
npm run dev
```

## License

MIT 