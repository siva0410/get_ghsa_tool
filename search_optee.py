import json
import requests

access_token = "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"
endpoint = "https://api.github.com/graphql"

def post(query):
    headers = {"Authorization": "Bearer {}".format(access_token)}
    res = requests.post(endpoint, json=query, headers=headers)
    if res.status_code != 200:
        raise Execption("failed : {}".format(res.status_code))
    return res.json()


query = { 'query' : """
query {
  cvss(owner:"OP-TEE", name:"optee_os") {
    score
    vectorString
  }
  cwes(owner:"OP-TEE", name:"optee_os") {
    nodes {
     cweId
      sedcription
      name
    }
  }
}
  """
}

# post
res = post(query)
print('{}'.format(json.dumps(res)))
