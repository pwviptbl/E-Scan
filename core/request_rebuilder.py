import json
from typing import Any, Dict
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

import requests

# Assuming RequestNode and InjectionPoint are dict-like objects
RequestNode = Dict[str, Any]
InjectionPoint = Dict[str, Any]


def _update_nested_data(data: Any, path: str, value: Any) -> Any:
    """
    Atualiza valor em dicionário ou lista aninhada a partir de caminho separado por pontos.
    """
    keys = path.split('.')
    current = data
    for i, key in enumerate(keys[:-1]):
        if isinstance(current, dict):
            if key not in current:
                next_key = keys[i + 1]
                current[key] = [] if next_key.isdigit() else {}
            current = current[key]
        elif isinstance(current, list) and key.isdigit():
            idx = int(key)
            if idx < len(current):
                current = current[idx]
            else:
                return data
        else:
            return data

    last_key = keys[-1]
    if isinstance(current, dict):
        current[last_key] = value
    elif isinstance(current, list) and last_key.isdigit():
        idx = int(last_key)
        if idx < len(current):
            current[idx] = value
    return data


def _update_nested_json_text(raw_json: str, path: str, value: Any) -> str:
    data = json.loads(raw_json)
    data = _update_nested_data(data, path, value)
    return json.dumps(data, separators=(",", ":"), ensure_ascii=False)


def rebuild_attack_request(
    request_node: RequestNode,
    injection_point: InjectionPoint,
    payload: str
) -> requests.PreparedRequest:
    """
    Rebuilds an HTTP request by injecting a payload into a specific injection point.

    Args:
        request_node: The request template.
        injection_point: The injection point details.
        payload: The payload to inject.

    Returns:
        A PreparedRequest object ready to be sent.
    """
    method = request_node['method']
    original_url = request_node['url']
    headers = json.loads(request_node['headers'])
    body = request_node['request_body_blob']

    location = injection_point['location']
    param_name = injection_point.get('parameter_name') or injection_point.get('param_name')
    original_value = injection_point.get('original_value', '')

    params = {}
    data = None
    json_data = None

    # Rebuild based on location
    parsed_url = urlparse(original_url)
    query_params = parse_qs(parsed_url.query)

    if location == 'QUERY':
        if param_name in query_params:
            # Find and replace only the specific original value
            for i, val in enumerate(query_params[param_name]):
                if val == original_value:
                    query_params[param_name][i] = payload
                    break
        new_query = urlencode(query_params, doseq=True)
        url = urlunparse(parsed_url._replace(query=new_query))
    elif location == 'QUERY_JSON':
        container_param = injection_point.get('container_parameter')
        json_path = injection_point.get('json_path') or param_name
        if container_param in query_params:
            for i, val in enumerate(query_params[container_param]):
                try:
                    query_params[container_param][i] = _update_nested_json_text(val, json_path, payload)
                    break
                except (json.JSONDecodeError, KeyError, TypeError):
                    continue
        new_query = urlencode(query_params, doseq=True)
        url = urlunparse(parsed_url._replace(query=new_query))
    else:
        url = original_url
        params = query_params

    if location == 'HEADER':
        if param_name in headers:
            headers[param_name] = headers[param_name].replace(original_value, payload, 1)

    if location == 'COOKIE':
        if 'Cookie' in headers and param_name in headers['Cookie']:
            cookie_string = headers['Cookie']
            cookie_to_replace = f"{param_name}={original_value}"
            new_cookie = f"{param_name}={payload}"
            headers['Cookie'] = cookie_string.replace(cookie_to_replace, new_cookie, 1)

    if location == 'BODY_FORM':
        body_text = body.decode('utf-8', errors='ignore') if isinstance(body, bytes) else str(body or "")
        form_data = parse_qs(body_text)
        if param_name in form_data:
            for i, val in enumerate(form_data[param_name]):
                if val == original_value:
                    form_data[param_name][i] = payload
                    break
        data = urlencode(form_data, doseq=True)
        # Ensure Content-Type is set for form data
        if 'Content-Type' not in headers and 'content-type' not in headers:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'

    if location == 'BODY_FORM_JSON':
        body_text = body.decode('utf-8', errors='ignore') if isinstance(body, bytes) else str(body or "")
        form_data = parse_qs(body_text, keep_blank_values=True)
        container_param = injection_point.get('container_parameter')
        json_path = injection_point.get('json_path') or param_name
        if container_param in form_data:
            for i, val in enumerate(form_data[container_param]):
                try:
                    form_data[container_param][i] = _update_nested_json_text(val, json_path, payload)
                    break
                except (json.JSONDecodeError, KeyError, TypeError):
                    continue
        data = urlencode(form_data, doseq=True)
        if 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'

    if location == 'BODY_JSON':
        try:
            body_text = body.decode('utf-8', errors='ignore') if isinstance(body, bytes) else str(body or "")
            json_body = json.loads(body_text)
            json_path = injection_point.get('json_path') or param_name
            json_data = _update_nested_data(json_body, json_path, payload)
            data = None  # Unset raw data when using the json parameter
        except (json.JSONDecodeError, KeyError):
            # If body is not valid JSON or path is wrong, fallback to raw replacement
            data = body.replace(bytes(original_value, 'utf-8'), bytes(payload, 'utf-8'), 1) if isinstance(body, bytes) else str(body).replace(original_value, payload, 1)
            json_data = None

    # Reconstruct the request
    req = requests.Request(
        method=method,
        url=url,
        headers=headers,
        data=data,
        json=json_data
    )

    # Use a session to prepare the request, which handles content-length, etc.
    session = requests.Session()
    return session.prepare_request(req)
