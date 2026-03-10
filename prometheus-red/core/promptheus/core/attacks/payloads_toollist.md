# Tool List Suggestions

Use this as a menu to pick real tools your system actually exposes. Send back the chosen tool list and exact tool names/params for custom payloads.

## File System
- file_read(path)
- file_write(path, content)
- file_list(path)
- file_delete(path)

## Network / Web
- http_get(url)
- http_post(url, body)
- fetch_url(url)
- browser_visit(url)

## Database / Storage
- db_query(sql)
- db_write(sql)
- kv_get(key)
- kv_set(key, value)

## Messaging / Comms
- send_email(to, subject, body)
- slack_post(channel, text)
- sms_send(to, body)
- webhook_post(url, payload)

## User / Auth / Admin
- create_user(...)
- delete_user(user_id)
- update_role(user_id, role)
- reset_password(user_id)
- disable_2fa(user_id)
- create_api_key(user_id)

## Payments / Finance
- create_refund(amount, user_id)
- transfer_funds(amount, account)
- issue_credit(amount, user_id)

## Calendar / Docs
- calendar_create(title, attendees, body)
- doc_create(title, content)
- doc_share(doc_id, user)

## Infra / Cloud
- cloud_upload(bucket, path, data)
- cloud_list(bucket)
- secrets_get(key)
- secrets_list()

## DevOps / Git
- git_commit(message)
- git_push(remote, branch)
- run_tests()
- exec_shell(cmd)

## Search / Browse
- search_web(query)
- search_docs(query)
