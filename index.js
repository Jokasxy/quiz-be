require('dotenv').config();
const { Keystone } = require('@keystonejs/keystone');
const { PasswordAuthStrategy } = require('@keystonejs/auth-password');
const { Text, Checkbox, Password, Url, Select, Relationship } = require('@keystonejs/fields');
const { GraphQLApp } = require('@keystonejs/app-graphql');
const { AdminUIApp } = require('@keystonejs/app-admin-ui');
const initialiseData = require('./initial-data');

const { MongooseAdapter: Adapter } = require('@keystonejs/adapter-mongoose');
const PROJECT_NAME = 'quiz';
const adapterConfig = { mongoUri: process.env.DATABASE_URL };


const keystone = new Keystone({
  adapter: new Adapter(adapterConfig),
  onConnect: process.env.CREATE_TABLES !== 'true' && initialiseData,
  cookieSecret: process.env.COOKIE_SECRET,
	cookie: {
		secure: false,
		maxAge: 1000 * 60 * 60 * 24 * 30,
		sameSite: false,
	}
});

// Access control functions
const userIsAdmin = ({ authentication: { item: user } }) => Boolean(user && user.isAdmin);
const userOwnsItem = ({ authentication: { item: user } }) => {
  if (!user) {
    return false;
  }

  // Instead of a boolean, you can return a GraphQL query:
  // https://www.keystonejs.com/api/access-control#graphqlwhere
  return { id: user.id };
};

const userIsAdminOrOwner = auth => {
  const isAdmin = access.userIsAdmin(auth);
  const isOwner = access.userOwnsItem(auth);
  return isAdmin ? isAdmin : isOwner;
};

const access = { userIsAdmin, userOwnsItem, userIsAdminOrOwner };

keystone.createList('User', {
  fields: {
    name: {
      type: Text,
      isRequired: true,
    },
    email: {
      type: Text,
      isUnique: true,
      isRequired: true,
    },
    isAdmin: {
      type: Checkbox,
      // Field-level access controls
      // Here, we set more restrictive field access so a non-admin cannot make themselves admin.
      access: {
        update: access.userIsAdmin,
      },
    },
    password: {
      type: Password,
      isRequired: true,
    },
  },
  // List-level access controls
  access: {
    read: access.userIsAdminOrOwner,
    update: access.userIsAdminOrOwner,
    create: access.userIsAdmin,
    delete: access.userIsAdmin,
    auth: true,
  },
});

keystone.createList('Answer', {
  fields: {
    name: {
      type: Text,
      isRequired: true,
    },
    description: {
      type: Text,
    },
  },
  // List-level access controls
  access: {
    read: true,
    update: access.userIsAdminOrOwner,
    create: access.userIsAdmin,
    delete: access.userIsAdmin,
    auth: true,
  },
});

keystone.createList('Question', {
  fields: {
    name: {
      type: Text,
    },
    image: {
      type: Url,
    },
    description: {
      type: Text,
      isRequired: true,
    },
    answers: {
      type: Relationship,
      ref: 'Answer',
      many: true,
    },
    correct: {
      type: Relationship,
      ref: 'Answer',
    },
  },
  // List-level access controls
  access: {
    read: true,
    update: access.userIsAdminOrOwner,
    create: access.userIsAdmin,
    delete: access.userIsAdmin,
    auth: true,
  },
});

keystone.createList('Feedback', {
  fields: {
    name: {
      type: Text,
    },
    image: {
      type: Url,
    },
    description: {
      type: Text,
      isRequired: true,
    },
    category: {
      type: Select,
      options: 'terrible, bad, ok, good, excellent',
      isRequired: true,
    },
  },
  // List-level access controls
  access: {
    read: true,
    update: access.userIsAdminOrOwner,
    create: access.userIsAdmin,
    delete: access.userIsAdmin,
    auth: true,
  },
});

keystone.createList('Quiz', {
  fields: {
    name: {
      type: Text,
      isRequired: true,
    },
    image: {
      type: Url,
    },
    description: {
      type: Text,
    },
    category: {
      type: Select,
      options: 'study, fun',
      isRequired: true,
    },
    questions: {
      type: Relationship,
      ref: 'Question',
      many: true,
      isRequired: true,
    },
    feedback: {
      type: Relationship,
      ref: 'Feedback',
      many: true,
      isRequired: true,
    },
  },
  // List-level access controls
  access: {
    read: true,
    update: access.userIsAdminOrOwner,
    create: access.userIsAdmin,
    delete: access.userIsAdmin,
    auth: true,
  },
});

const authStrategy = keystone.createAuthStrategy({
  type: PasswordAuthStrategy,
  list: 'User',
});

module.exports = {
  keystone,
  apps: [
    new GraphQLApp(),
    new AdminUIApp({
      name: PROJECT_NAME,
      enableDefaultRoute: true,
      authStrategy,
    }),
  ],
  configureExpress: app => {
		app.set('trust proxy', 1);
	},
};
