# 📣 Bulletin Board API

*(This file was generated using AI.)*

This is the backend API for a mobile app designed to facilitate group-based communication and posting, inspired by Harvard’s HIVE. It powers all core functionality of the mobile application — from group discovery to member management and posting.

> ⚠️ This project was built rapidly and may lack in areas such as optimization, validation depth, or extensibility. Contributions and improvements are very welcome.

## 📦 Features

### 🧑‍🤝‍🧑 Group Management

* Search and create public groups
* Edit, and delete groups
* Group whitelist/blacklist support (emails and domains)
* View joined and created groups separately

### 👥 Membership

* Join group (enforces whitelist/blacklist rules)
* Leave group (restricted if banned or admin)
* List all group members (admin-only)
* Ban members (admin-only)

### 📝 Posts

* Create, edit, delete posts in groups (admin-only)
* View posts in a group (members only, if not banned)

### 🚀 Getting Started

#### Prerequisites

* Python 3.14+ (*Not tested on previous versions but should work 3.10+*)
* PostgreSQL
* Redis

### Installation

```bash
git clone https://github.com/yourusername/bulletin-board-api.git
cd bulletin-board-api
pip install -r requirements.txt
touch .env
python manage.py migrate
python manage.py runserver
```

The ```.env``` allows the following fields, of which certain are required.

* ```SECRET_KEY```
* ```DB_PASSWORD```
* ```DEBUG```
* ```ALLOWED_HOSTS```
* ```CORS_ALLOWED_ORIGINS```
* ```DB_NAME```
* ```DB_USER```
* ```DB_PASSWORD```
* ```DB_HOST```
* ```DB_PORT```
* ```EMAIL_HOST```
* ```EMAIL_HOST_USER```
* ```EMAIL_HOST_PASSWORD```
* ```DEFAULT_FROM_EMAIL```
* ```EMAIL_HOST```
* ```EMAIL_PORT```
* ```EMAIL_USE_TLS```
* ```EMAIL_USE_SSL```
* ```EMAIL_HOST_USER```
* ```EMAIL_HOST_PASSWORD```
* ```DEFAULT_FROM_EMAIL```
* ```REDIS_HOST```
* ```REDIS_PORT```
* ```REDIS_DB```
* ```REDIS_USER```
* ```REDIS_PASSWORD```

### 🤝 Contributing

This project is a work in progress and contributions are highly appreciated. Whether it's a bug fix, feature addition, or performance tweak — feel free to open an issue or PR.
