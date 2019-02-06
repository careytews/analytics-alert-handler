# Alert handler
## Building
Alert Handler has to be built in a docker container for deployment
but it can also be built locally for dev purposes
### Locally / Natively
`make local` from the top level, this will first ensure all deps are
available, then build
### In container
`make build` will build in the container including getting the deps.
Container used will be `gcr.io/trust-networks/analytic-builder`
which is built from `github.com/trustnetworks/analytic-builder`

Deps are shared between the two build approaches, so if you have
built locally and got the dependencies it will be quick to build in
the container

## Releasing
*SHOULD BE DONE BY GoCD!!!*
```
make all VERSION=X
make push VERSION=X
```
will build in the container then create a container with the binary
in, and push it to GCR.
