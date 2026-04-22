import { apiSlice } from './apiSlice';

const POSTS_URL = '/api/posts';

export const postApiSlice = apiSlice.injectEndpoints({
  endpoints: (builder) => ({
    createPost: builder.mutation({
      query: (data) => ({
        url: POSTS_URL,
        method: 'POST',
        body: data
      }),
      invalidatesTags: ['Post']
    }),
    getMyPosts: builder.query({
      query: (q = '') => ({
        url: `${POSTS_URL}/my`,
        params: q ? { q } : undefined
      }),
      providesTags: ['Post']
    }),
    getPublicPosts: builder.query({
      query: (q = '') => ({
        url: `${POSTS_URL}/public`,
        params: q ? { q } : undefined
      }),
      providesTags: ['Post']
    }),
    updatePost: builder.mutation({
      query: ({ id, ...data }) => ({
        url: `${POSTS_URL}/${id}`,
        method: 'PUT',
        body: data
      }),
      invalidatesTags: ['Post']
    }),
    setPostVisibility: builder.mutation({
      query: ({ id, visibility }) => ({
        url: `${POSTS_URL}/${id}/visibility`,
        method: 'PATCH',
        body: { visibility }
      }),
      invalidatesTags: ['Post']
    }),
    deletePost: builder.mutation({
      query: (id) => ({
        url: `${POSTS_URL}/${id}`,
        method: 'DELETE'
      }),
      invalidatesTags: ['Post']
    })
  })
});

export const {
  useCreatePostMutation,
  useGetMyPostsQuery,
  useGetPublicPostsQuery,
  useUpdatePostMutation,
  useSetPostVisibilityMutation,
  useDeletePostMutation
} = postApiSlice;
