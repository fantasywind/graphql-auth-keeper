# graphql-auth-keeper
Endpoint Auth Keeper for GraphQL Application

## Example

### Member Action Check
```javascript
import {
  GraphQLInt,
  GraphQLNonNull,
  GraphQLString,
} from 'graphql';
import Koa from 'koa';
import Router from 'koa-router';
import koaBody from 'koa-bodyparser';
import { graphqlKoa, graphiqlKoa } from 'apollo-server-koa';
import graphqlAuthKeeper, {
  authKeeper,
  FLAG,
} from 'graphql-auth-keeper';
import { db } from './db.js';

const CREATE_MEMBER = {
  name: 'Create Member',
  code: 1,
};

const graphqlHandler = graphqlKoa(ctx => ({
  schema,
  context: {
    [FLAG]: graphqlAuthKeeper(ctx, payload => db.models.Member.findOne({
      where: {
        id: payload.id,
      },
    })),
  },
});

const createMemberMutation = {
  type: GraphQLInt,
  args: {
    account: {
      type: new GraphQLNonNull(GraphQLString),
    },
    password: {
      type: new GraphQLNonNull(GraphQLString),
    },
  },
  resolve: authKeeper({
    onFailed: new Error('Auth Failed'),
    actions: CREATE_MEMBER,    
  })(async (member, {
    account,
    password,
  }) => {
    const createdMember = await db.models.Member.create({
      account,
      password,
      CreatorId: member.id,
    });

    return createdMember.id;
  }),
};

const app = new Koa();
const router = new Router();

router.post('/graphql', koaBody(), graphqlHandler);
router.get('/graphql', graphqlHandler);

app.use(router.routes());
app.use(router.allowedMethods());

app.listen(3000);
```

## Keeper API

graphqlAuthKeeper(KoaContext, [SyncFunctionForOnlineDataMode])

## Keeper Options

- logined(boolean): Require valid JWT token or not
- actions(Action | Array<Action>): Required actions
- onlineData(boolean): Should return online (syncd) data on resolve payload
- onFailed(Error | Function | any): If Error given will throw it. Function will execute and return it result or return data directly.
- orMode(boolean): The actions should be match all or partial.
