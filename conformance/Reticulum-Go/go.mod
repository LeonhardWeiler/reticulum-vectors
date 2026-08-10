module q4ret

go 1.26.5

require (
	quad4/msgpack/v5 v5.8.1
	quad4/reticulum-go v0.0.0
)

require (
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	golang.org/x/crypto v0.53.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	quad4/bzip2 v0.0.0 // indirect
	quad4/tagparser v0.0.0 // indirect
)

replace (
	quad4/bzip2 => ../src/Reticulum-Go-Projects/bzip2
	quad4/msgpack/v5 => ../src/Reticulum-Go-Projects/msgpack
	quad4/pbt => ../src/Reticulum-Go-Projects/pbt
	quad4/reticulum-go => ../src/Reticulum-Go
	quad4/tagparser => ../src/Reticulum-Go-Projects/tagparser
)
