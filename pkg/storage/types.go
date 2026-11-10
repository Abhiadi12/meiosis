package storage

import "context"

// Tx is an atomic storage operation. Returning an error from the transaction
// callback rolls back every operation performed through tx.
type Tx interface {
	Put(ctx context.Context, kind Kind, key string, value []byte) error
	Get(ctx context.Context, kind Kind, key string) ([]byte, error)
	Delete(ctx context.Context, kind Kind, key string) error
	List(ctx context.Context, kind Kind) (map[string][]byte, error)
	PutBlob(ctx context.Context, value []byte) (BlobID, error)
	GetBlob(ctx context.Context, id BlobID) ([]byte, error)
}

// Store persists serialized Meiosis records without exposing backend details
// to callers. Implementations must copy data they retain or return.
type Store interface {
	Put(ctx context.Context, kind Kind, key string, value []byte) error
	Get(ctx context.Context, kind Kind, key string) ([]byte, error)
	Delete(ctx context.Context, kind Kind, key string) error
	List(ctx context.Context, kind Kind) (map[string][]byte, error)
	PutBlob(ctx context.Context, value []byte) (BlobID, error)
	GetBlob(ctx context.Context, id BlobID) ([]byte, error)
	Transaction(ctx context.Context, fn func(Tx) error) error
	Close() error
}
