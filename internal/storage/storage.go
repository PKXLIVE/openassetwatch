package storage

import "context"

type Store[T any] interface {
	Save(ctx context.Context, value T) error
	List(ctx context.Context) ([]T, error)
}
