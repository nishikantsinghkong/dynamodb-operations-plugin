# dynamodb-operations-plugin
The code in this repo will highlight how to use Lua scripts to formulate requests and perform different AWS dynamodb operations from Kong plugin

Note: 1. the current handler.lua code is expected to run on EC2 instance, where it grabs the temp session token and uses it for connecting with dyanmodb instance
2. Region is extracted from the input scheam, with us-east-2 as a default value
3.
