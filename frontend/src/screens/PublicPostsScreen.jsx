import { useState } from 'react';
import { FaGlobe, FaRegStickyNote } from 'react-icons/fa';
import Loader from '../components/Loader';
import { useGetPublicPostsQuery } from '../slices/postApiSlice';

const PublicPostsScreen = () => {
  const [searchText, setSearchText] = useState('');
  const { data: posts, isLoading, isError, error } = useGetPublicPostsQuery(searchText.trim());

  return (
    <div className="min-h-screen bg-slate-50 py-10 px-4 sm:px-6 lg:px-8">
      <div className="max-w-6xl mx-auto">
        <div className="bg-white border border-slate-200 rounded-2xl p-6 md:p-8 shadow-sm mb-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-10 h-10 rounded-xl bg-emerald-100 text-emerald-700 flex items-center justify-center">
              <FaGlobe />
            </div>
            <div>
              <h1 className="text-2xl md:text-3xl font-bold text-slate-900">Public Posts</h1>
              <p className="text-slate-600 text-sm md:text-base">Discover posts shared publicly by users.</p>
            </div>
          </div>

          <label className="block text-sm font-semibold text-slate-700 mb-2">Search Public Posts</label>
          <input
            type="text"
            value={searchText}
            onChange={(e) => setSearchText(e.target.value)}
            placeholder="Search by title or content"
            className="w-full border border-slate-300 rounded-xl px-4 py-3 focus:outline-none focus:ring-2 focus:ring-emerald-500"
          />
        </div>

        <div className="bg-white border border-slate-200 rounded-2xl p-6 md:p-8 shadow-sm">
          {isLoading ? (
            <Loader />
          ) : isError ? (
            <p className="text-red-600">{error?.data?.message || error?.error || 'Failed to load public posts'}</p>
          ) : posts?.length === 0 ? (
            <div className="border border-dashed border-slate-300 rounded-xl p-8 text-center text-slate-500">
              <FaRegStickyNote className="mx-auto mb-3 text-2xl" />
              <p>No public posts found.</p>
              <p className="text-sm mt-2">Create a post and set visibility to Public from My Secure Posts.</p>
            </div>
          ) : (
            <div className="space-y-4">
              {posts.map((post) => (
                <article key={post._id} className="border border-slate-200 rounded-xl p-4 md:p-5">
                  <h3 className="text-lg font-semibold text-slate-900 mb-2">{post.title}</h3>
                  <p className="text-slate-700 whitespace-pre-wrap">{post.content}</p>
                  <p className="text-xs text-slate-500 mt-3">
                    Published {new Date(post.createdAt).toLocaleString()}
                  </p>
                </article>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default PublicPostsScreen;
