# Hack Club Dashboard

A comprehensive, modularized dashboard system for Hack Club leaders to manage their clubs, track attendance, manage projects, and engage with their community.

## 🎉 Fully Modularized Architecture

This application has been completely refactored from a monolithic 16,000+ line file into a clean, maintainable, modular structure with proper separation of concerns.

## ✨ Features

- **Club Management**: Create and manage your Hack Club
- **Attendance Tracking**: Track member attendance and generate reports
- **Project Gallery**: Showcase club projects and achievements
- **Blog System**: Share updates, announcements, and stories
- **Shop System**: Order supplies and materials for your club
- **Token Economy**: Reward members with tokens for participation
- **Chat System**: Club messaging and communication
- **Admin Panel**: Comprehensive administration and moderation tools
- **OAuth Server**: Third-party application integration
- **Status Page**: Monitor system health and incidents

## 📁 Project Structure

```
├── app/
│   ├── __init__.py           # Application factory
│   ├── decorators/           # Auth, permissions, rate limiting
│   ├── models/               # Database models (13 files)
│   ├── routes/               # Route blueprints (10 blueprints)
│   ├── services/             # External API integrations
│   └── utils/                # Helper functions
├── config.py                # Configuration management
├── extensions.py            # Flask extensions
├── main.py                  # Application entry point
└── requirements.txt         # Python dependencies
```

## 🚀 Quick Start

### Install & Run

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables in .env file (see Configuration section)

# Initialize database
python init_db.py

# Run application
python main.py
```

## 🔧 Configuration

Create a `.env` file:

```env
DATABASE_URL=postgresql://user:password@localhost/hackclub_dashboard
SECRET_KEY=your-secret-key-here
SLACK_CLIENT_ID=your-slack-client-id
SLACK_CLIENT_SECRET=your-slack-client-secret
HC_IDENTITY_CLIENT_ID=your-hc-identity-client-id
HC_IDENTITY_CLIENT_SECRET=your-hc-identity-client-secret
PORT=5000
```

## 📚 Learn More

- **Architecture**: Application factory pattern with 10 blueprints
- **Security**: CSRF, XSS, SQL injection protection, rate limiting
- **Database**: PostgreSQL with SQLAlchemy ORM
- **Auth**: Slack OAuth, Hack Club Identity OAuth, session-based

---

**Built with ❤️ for the Hack Club community**
