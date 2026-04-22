import { useMemo, useState } from 'react';
import { toast } from 'react-toastify';
import {
  useCreatePostMutation,
  useDeletePostMutation,
  useGetMyPostsQuery,
  useSetPostVisibilityMutation,
  useUpdatePostMutation
} from '../slices/postApiSlice';
import Loader from '../components/Loader';
import ConfirmActionModal from '../components/ConfirmActionModal.jsx';
import { FaEdit, FaGlobe, FaLock, FaPlus, FaRegStickyNote, FaSave, FaTrash } from 'react-icons/fa';

const emptyForm = { title: '', content: '' };

const MyPostsScreen = () => {
  const [form, setForm] = useState(emptyForm);
  const [editingPostId, setEditingPostId] = useState('');
  const [searchText, setSearchText] = useState('');
  const [visibility, setVisibility] = useState('private');
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [postToDelete, setPostToDelete] = useState(null);

  const {
    data: posts,
    isLoading,
    isError,
    error,
    refetch
  } = useGetMyPostsQuery(searchText.trim());

  const [createPost, { isLoading: isCreating }] = useCreatePostMutation();
  const [updatePost, { isLoading: isUpdating }] = useUpdatePostMutation();
  const [setPostVisibility, { isLoading: isChangingVisibility }] = useSetPostVisibilityMutation();
  const [deletePost, { isLoading: isDeleting }] = useDeletePostMutation();

  const submitLabel = useMemo(() => (editingPostId ? 'Update Post' : 'Create Post'), [editingPostId]);

  const submitHandler = async (e) => {
    e.preventDefault();
    if (!form.title.trim() || !form.content.trim()) {
      toast.error('Title and content are required');
      return;
    }

    try {
      if (editingPostId) {
        await updatePost({
          id: editingPostId,
          title: form.title.trim(),
          content: form.content.trim(),
          visibility
        }).unwrap();
        toast.success('Post updated successfully');
      } else {
        await createPost({ title: form.title.trim(), content: form.content.trim(), visibility }).unwrap();
        toast.success('Post created successfully');
      }

      setForm(emptyForm);
      setEditingPostId('');
      setVisibility('private');
      refetch();
    } catch (err) {
      toast.error(err?.data?.message || err?.error || 'Failed to save post');
    }
  };

  const startEdit = (post) => {
    setEditingPostId(post._id);
    setForm({ title: post.title || '', content: post.content || '' });
    setVisibility(post.visibility || 'private');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const resetForm = () => {
    setEditingPostId('');
    setForm(emptyForm);
    setVisibility('private');
  };

  const openDeleteModal = (post) => {
    setPostToDelete(post);
    setShowDeleteConfirm(true);
  };

  const changePostVisibility = async (post, nextVisibility) => {
    try {
      await setPostVisibility({ id: post._id, visibility: nextVisibility }).unwrap();

      if (editingPostId === post._id) {
        setVisibility(nextVisibility);
      }

      toast.success(`Post is now ${nextVisibility}`);
      refetch();
    } catch (err) {
      toast.error(err?.data?.message || err?.error || 'Failed to update post privacy');
    }
  };

  const confirmDeletePost = async () => {
    if (!postToDelete?._id) return;

    try {
      await deletePost(postToDelete._id).unwrap();
      toast.success('Post deleted successfully');
      if (editingPostId === postToDelete._id) {
        resetForm();
      }
      setShowDeleteConfirm(false);
      setPostToDelete(null);
      refetch();
    } catch (err) {
      toast.error(err?.data?.message || err?.error || 'Failed to delete post');
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 py-10 px-4 sm:px-6 lg:px-8">
      <div className="max-w-7xl mx-auto mb-6">
        <label className="block text-sm font-semibold text-slate-700 mb-2">Search Posts</label>
        <input
          type="text"
          value={searchText}
          onChange={(e) => setSearchText(e.target.value)}
          placeholder="Search by title or content"
          className="w-full border border-slate-300 rounded-xl px-4 py-3 focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white"
        />
      </div>

      <div className="max-w-7xl mx-auto grid grid-cols-1 lg:grid-cols-2 gap-8 items-start">
        <div className="bg-white border border-slate-200 rounded-2xl p-6 md:p-8 shadow-sm lg:sticky lg:top-24">
          <div className="flex items-center gap-3 mb-6">
            <div className="w-10 h-10 rounded-xl bg-blue-100 text-blue-700 flex items-center justify-center">
              {editingPostId ? <FaEdit /> : <FaPlus />}
            </div>
            <div>
              <h1 className="text-2xl md:text-3xl font-bold text-slate-900">My Secure Posts</h1>
              <p className="text-slate-600 text-sm md:text-base">Create, edit, and manage your encrypted posts.</p>
            </div>
          </div>

          <form onSubmit={submitHandler} className="space-y-4">
            <div>
              <label className="block text-sm font-semibold text-slate-700 mb-2">Title</label>
              <input
                type="text"
                value={form.title}
                onChange={(e) => setForm((prev) => ({ ...prev, title: e.target.value }))}
                placeholder="Enter your post title"
                className="w-full border border-slate-300 rounded-xl px-4 py-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>

            <div>
              <label className="block text-sm font-semibold text-slate-700 mb-2">Content</label>
              <textarea
                rows={6}
                value={form.content}
                onChange={(e) => setForm((prev) => ({ ...prev, content: e.target.value }))}
                placeholder="Write your post content"
                className="w-full border border-slate-300 rounded-xl px-4 py-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>

            <div>
              <label className="block text-sm font-semibold text-slate-700 mb-2">Who can view this post?</label>
              <select
                value={visibility}
                onChange={(e) => setVisibility(e.target.value)}
                className="w-full border border-slate-300 rounded-xl px-4 py-3 focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white"
              >
                <option value="private">Private (only me)</option>
                <option value="public">Public (all users)</option>
              </select>
            </div>

            <div className="flex gap-3">
              <button
                type="submit"
                disabled={isCreating || isUpdating}
                className="inline-flex items-center gap-2 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-300 text-white px-5 py-3 rounded-xl font-semibold transition-colors"
              >
                <FaSave />
                {submitLabel}
              </button>

              {editingPostId && (
                <button
                  type="button"
                  onClick={resetForm}
                  className="inline-flex items-center gap-2 border border-slate-300 text-slate-700 px-5 py-3 rounded-xl font-semibold hover:bg-slate-100"
                >
                  Cancel Edit
                </button>
              )}
            </div>
          </form>
        </div>

        <div className="bg-white border border-slate-200 rounded-2xl p-6 md:p-8 shadow-sm">
          <h2 className="text-xl md:text-2xl font-bold text-slate-900 mb-5">Saved Posts</h2>
          {searchText.trim() && (
            <p className="text-sm text-slate-500 mb-4">
              Showing results for "{searchText.trim()}"
            </p>
          )}

          {isLoading ? (
            <Loader />
          ) : isError ? (
            <p className="text-red-600">{error?.data?.message || error?.error || 'Failed to load posts'}</p>
          ) : posts?.length === 0 ? (
            <div className="border border-dashed border-slate-300 rounded-xl p-8 text-center text-slate-500">
              <FaRegStickyNote className="mx-auto mb-3 text-2xl" />
              <p>No posts yet. Create your first one above.</p>
            </div>
          ) : (
            <div className="space-y-4">
              {posts.map((post) => (
                <article key={post._id} className="border border-slate-200 rounded-xl p-4 md:p-5">
                  <div className="flex flex-wrap items-start justify-between gap-3 mb-2">
                    <h3 className="text-lg font-semibold text-slate-900">{post.title}</h3>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => startEdit(post)}
                        className="inline-flex items-center gap-2 text-sm px-3 py-2 rounded-lg border border-slate-300 text-slate-700 hover:bg-slate-100"
                      >
                        <FaEdit />
                        Edit
                      </button>
                      {post.visibility === 'public' ? (
                        <button
                          onClick={() => changePostVisibility(post, 'private')}
                          disabled={isChangingVisibility}
                          className="inline-flex items-center gap-2 text-sm px-3 py-2 rounded-lg border border-amber-300 text-amber-700 hover:bg-amber-50 disabled:opacity-50"
                        >
                          <FaLock />
                          Make Private
                        </button>
                      ) : (
                        <button
                          onClick={() => changePostVisibility(post, 'public')}
                          disabled={isChangingVisibility}
                          className="inline-flex items-center gap-2 text-sm px-3 py-2 rounded-lg border border-emerald-300 text-emerald-700 hover:bg-emerald-50 disabled:opacity-50"
                        >
                          <FaGlobe />
                          Make Public
                        </button>
                      )}
                      <button
                        onClick={() => openDeleteModal(post)}
                        disabled={isDeleting}
                        className="inline-flex items-center gap-2 text-sm px-3 py-2 rounded-lg bg-red-600 text-white hover:bg-red-700 disabled:bg-red-300"
                      >
                        <FaTrash />
                        Delete
                      </button>
                    </div>
                  </div>
                  <p className="text-slate-700 whitespace-pre-wrap">{post.content}</p>
                  <p className="text-xs mt-3">
                    <span className={`px-2 py-1 rounded-full ${post.visibility === 'public' ? 'bg-emerald-100 text-emerald-700' : 'bg-amber-100 text-amber-700'}`}>
                      {post.visibility === 'public' ? 'Public' : 'Private'}
                    </span>
                  </p>
                  <p className="text-xs text-slate-500 mt-3">
                    Updated {new Date(post.updatedAt || post.createdAt).toLocaleString()}
                  </p>
                </article>
              ))}
            </div>
          )}
        </div>
      </div>

      <ConfirmActionModal
        show={showDeleteConfirm}
        title="Delete Post"
        message={`This action cannot be undone. The post "${postToDelete?.title || 'Untitled'}" will be permanently deleted.`}
        confirmLabel="Delete Post"
        loadingLabel="Deleting..."
        onConfirm={confirmDeletePost}
        onClose={() => {
          if (!isDeleting) {
            setShowDeleteConfirm(false);
            setPostToDelete(null);
          }
        }}
        isLoading={isDeleting}
      />
    </div>
  );
};

export default MyPostsScreen;
