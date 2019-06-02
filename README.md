# Node Express Passport.js Dropbox Example


### Set up postgres

1. heroku addons:create heroku-postgresql:hobby-dev
2. heroku config
3. Copy the POSTGRES_URL to .env file
4. Connect to db and import the users table in db.sql file


## Set up Dropbox Application

1. Create or use existing dropbox app from developer https://www.dropbox.com/developers/apps
2. Copy app id and secret to environment variables
  i. Put env variables in .env file
  ii. Set up deployment (heroku in this example) env variables
3. Set up redirect urls in the app in DropboxStrategy object config
4. Add the callback urls to Dropbox app's whitelisted redirect urls


### Env File

You need to create and place all configuration about your database, Dropbox app details in .env file or in your target platform's environment variables. The env file or variables listed below:

```
DATABASE_URL=postgres://...
DROPBOX_CLIENT_ID=9d024....
DROPBOX_CLIENT_SECRET=082fd...
DROPBOX_CALLBACK_URL=https://...
```

### Run

1. npm install
2. node index.js


### Deploy on heroku

1. git init
2. heroku login
3. heroku create
4. git push heroku master