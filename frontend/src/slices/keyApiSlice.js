import { apiSlice } from "./apiSlice";

const KEYS_URL = '/api/keys';

export const keysApiSlice = apiSlice.injectEndpoints({
    endpoints: (builder) => ({
        getKeys: builder.query({
            query: () => ({
                url: KEYS_URL,
            }),
        }),
        getKeyStatus: builder.query({
            query: () => ({
                url: `${KEYS_URL}/status`,
            }),
        }),
        rotateKey: builder.mutation({
            query: (keyId) => ({
                url: `${KEYS_URL}/rotate/${keyId}`,
                method: 'POST',
            }),
        }),
        revokeKey: builder.mutation({
            query: (keyId) => ({
                url: `${KEYS_URL}/revoke/${keyId}`,
                method: 'POST',
            }),
        }),
    })
});

export const {
    useGetKeysQuery,
    useGetKeyStatusQuery,
    useRotateKeyMutation,
    useRevokeKeyMutation,
} = keysApiSlice;
