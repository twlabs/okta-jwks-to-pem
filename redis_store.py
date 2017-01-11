
def save_pem_keys(redis_url, json_web_keys, pem_keys):
    import redis

    redis_client = redis.from_url(redis_url)
    for jwk, pem in zip(json_web_keys['keys'], pem_keys):
        redis_client.hset('okta_public_keys', jwk['kid'], pem)
    print('Public keys were stored in redis successfully')
