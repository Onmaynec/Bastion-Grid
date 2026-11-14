"""Asset/case attributes are evaluated in addition to role permissions."""
import json

SENSITIVITY = {'public': 0, 'internal': 1, 'confidential': 2, 'restricted': 3}
DEFAULT_POLICY = {'groups': ['*'], 'max_sensitivity': 'restricted', 'assigned_only': False}


def policy_of(principal):
    # Internal workers and pre-v2 internal fixtures have no persisted policy field.
    raw = principal.get('policy')
    if 'policy' not in principal and 'token_hash' not in principal:
        return dict(DEFAULT_POLICY)
    try:
        policy = json.loads(raw) if isinstance(raw, str) else raw
        if (not isinstance(policy, dict) or set(policy) != set(DEFAULT_POLICY)
                or not isinstance(policy['groups'], list)
                or not all(isinstance(g, str) and g for g in policy['groups'])
                or policy['max_sensitivity'] not in SENSITIVITY
                or type(policy['assigned_only']) is not bool):
            raise ValueError('invalid policy')
        return policy
    except (ValueError, TypeError, KeyError):
        return {'groups': [], 'max_sensitivity': 'public', 'assigned_only': True}


def unrestricted(principal):
    policy = policy_of(principal)
    return ('*' in policy['groups'] and policy['max_sensitivity'] == 'restricted'
            and not policy['assigned_only'])


def asset_allowed(principal, asset):
    policy = policy_of(principal)
    group = asset.get('group', 'lab')
    sensitivity = asset.get('sensitivity', 'internal')
    return (('*' in policy['groups'] or group in policy['groups'])
            and sensitivity in SENSITIVITY
            and SENSITIVITY[sensitivity] <= SENSITIVITY[policy['max_sensitivity']])
