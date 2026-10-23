A prototype script for testing RabbitMQ authentication & authorization over JWT

Usage:

```
$ cd /path/to/the/working/directory
$ mvn compile exec:java "-Dexec.args=generate-keys"
$ docker compose up -d
$ mvn compile exec:java "-Dexec.args=test"
```