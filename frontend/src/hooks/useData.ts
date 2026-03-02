/** Generic typed fetch hook built on react-query's useQuery. */
import { useQuery } from '@tanstack/react-query'

export function useData<T>(key: unknown[], fetcher: () => Promise<T>) {
  return useQuery<T>({
    queryKey: key,
    // Wrap in an arrow function so React Query's QueryFunctionContext is not
    // passed as the first argument to fetcher (which would clobber default
    // params like `bucket` and `n`, causing 422 responses).
    queryFn: () => fetcher(),
    // Stale immediately so SSE invalidation always triggers a refetch
    staleTime: 0,
    refetchOnWindowFocus: false,
  })
}
