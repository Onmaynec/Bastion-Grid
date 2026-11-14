"""Bounded predicates and fixture evaluation shared by detection and replay."""
import math
from datetime import datetime, timezone
from .core import exact_fields, require

FIELDS = {'event_type', 'outcome', 'process_name', 'severity'}


def predicate(value):
    exact_fields(value, ['field', 'operator', 'value'], ['field', 'operator', 'value'])
    require(isinstance(value['field'], str) and value['field'] in FIELDS)
    require(isinstance(value['operator'], str) and value['operator'] in {'eq', 'gte', 'contains'})
    expected = value['value']
    require(type(expected) in (str, int, float) and len(str(expected)) <= 200)
    require(not isinstance(expected, float) or math.isfinite(expected))
    if value['operator'] == 'gte':
        require(type(expected) in (int, float))
    if value['operator'] == 'contains':
        require(isinstance(expected, str) and bool(expected))
    return dict(value)


def conditions(rule):
    return rule['conditions'] if 'conditions' in rule else [{k: rule[k] for k in ('field', 'operator', 'value')}]


def evaluate(rule, event):
    results = []
    for condition in conditions(rule):
        actual, expected = event['attributes'].get(condition['field']), condition['value']
        op = condition['operator']
        if op == 'eq':
            matched = type(actual) is type(expected) and actual == expected
        elif op == 'gte':
            matched = type(actual) in (int, float) and actual >= expected
        else:
            matched = isinstance(actual, str) and expected in actual
        results.append(matched)
    return {'matched': (any(results) if rule.get('match', 'all') == 'any' else all(results)),
            'conditions': results}


def timestamp(value):
    require(isinstance(value, str) and 1 <= len(value) <= 200, 'invalid_time')
    try:
        stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
        require(stamp.tzinfo is not None, 'invalid_time', 'Требуется часовой пояс')
        return stamp.astimezone(timezone.utc).isoformat(timespec='microseconds')
    except (ValueError, OverflowError):
        require(False, 'invalid_time', 'Требуется ISO 8601 с часовым поясом')
