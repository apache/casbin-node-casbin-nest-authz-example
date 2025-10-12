import * as casbin from 'casbin';
import * as path from 'path';

let enforcer: casbin.Enforcer;
const modelPath = path.join(__dirname, '../model.conf');
const policyPath = path.join(__dirname, '../policy.csv');

beforeEach(async () => {
  enforcer = await casbin.newEnforcer(modelPath, policyPath);
});

describe('Root user root', () => {
  it('can read any user roles', async () => {
    const result = await enforcer.enforce('root', 'user_roles', 'read:any');
    expect(result).toBe(true);
  });
  it('can read any user', async () => {
    const result = await enforcer.enforce('root', 'user', 'read:any');
    expect(result).toBe(true);
  });
});

describe('manager tom', () => {
  it('can read any user roles', async () => {
    const result = await enforcer.enforce('tom', 'user_roles', 'read:any');
    expect(result).toBe(true);
  });
  it('can not read any user', async () => {
    const result = await enforcer.enforce('tom', 'user', 'read:any');
    expect(result).toBe(false);
  });
});

describe('guest bob', () => {
  it('can read own user', async () => {
    const result = await enforcer.enforce('bob', 'user', 'read:own');
    expect(result).toBe(true);
  });
  it('can not read any user', async () => {
    const result = await enforcer.enforce('bob', 'user', 'read:any');
    expect(result).toBe(false);
  });
});

describe('Resource hierarchy with g2', () => {
  it('manager can access user_roles directly', async () => {
    const result = await enforcer.enforce('tom', 'user_roles', 'read:any');
    expect(result).toBe(true);
  });
  it('superuser can access user resource group', async () => {
    const result = await enforcer.enforce('alice', 'user', 'read:any');
    expect(result).toBe(true);
  });
  it('superuser can access users_list through user resource group hierarchy', async () => {
    // superuser has permission on 'user', and 'users_list' is in 'user' group (via g2)
    const result = await enforcer.enforce('alice', 'users_list', 'read:any');
    expect(result).toBe(true);
  });
  it('superuser can access user_roles through user resource group hierarchy', async () => {
    // superuser has permission on 'user', and 'user_roles' is in 'user' group (via g2)
    const result = await enforcer.enforce('alice', 'user_roles', 'read:any');
    expect(result).toBe(true);
  });
  it('superuser cannot access role_permissions (not in user group)', async () => {
    // superuser only has permission on 'user', not 'role'
    // 'role_permissions' is in 'role' group, not 'user' group
    const result = await enforcer.enforce('alice', 'role_permissions', 'read:any');
    expect(result).toBe(false);
  });
});
