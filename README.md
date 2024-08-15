# WIZAPI
This module provides a Python interface for making API calls to the Wiz.

## Installation

```bash
pip install wizapi
```

## Usage
Class: WIZ
The Wiz class is designed to interact with the Wiz API. It manages authentication via OAuth2 and supports making requests to the API.

```python
from wizapi import WIZ

# Initialize the API client
w = WIZ(
    client_id="your_client_id",
    client_secret="your_client_secret",
    api_url="https://api.myapp.com",
    auth_url="https://auth.myapp.com/token",
)

GRAPH_QUERY ="""..."""
GRAPH_VARIABLE={...}
# Make an authenticated API call
result = w.query(query= GRAPH_QUERY, variables=GRAPH_VARIABLE)
print(result)
```

It supports retrieving configuration from an INI file, JSON file, or environment variables. The module requires a wiz directory in the home directory (~/.api) with the following structure:

```
~/.wiz/
      ├── config # ini config
      ├── config.json # json config
      └── credentials/
          └── credentials_....json # stored access key

```

The module allows reusing the access token until it expires by setting `stored=True` when initializing the Wiz class.

```python
w=Wiz(stored=True)
```


## Methods
- `query()` : non-paginated query result (dict)
- `query_all()`: paginated query result (dict)
