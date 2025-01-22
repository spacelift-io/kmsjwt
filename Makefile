
.PHONY: localstack
localstack:
	docker run --rm -it -e SERVICES="kms" -p 4566:4566 localstack/localstack:4.0.3
