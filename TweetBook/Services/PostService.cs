﻿using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using TweetBook.Data;
using TweetBook.Domain;

namespace TweetBook.Services
{
    public class PostService : IPostService
    {
        private readonly DataContext _dataContext;

        public PostService(DataContext dataContext)
        {
            _dataContext = dataContext;
        }
        

        public async Task<Post> GetPostByIdAsync(Guid postId)
        {
            return await _dataContext.Posts.FirstOrDefaultAsync(x => x.Id == postId);
        }


        public async Task<List<Post>> GetPostsAsync()
        {
            return await _dataContext.Posts.ToListAsync(); ;
        }

        public async Task<bool> UpdatePostAsync(Post postToUpdate)
        {
            _dataContext.Posts.Update(postToUpdate);
            var updated = await _dataContext.SaveChangesAsync();
            return updated > 0;
        }

        public async Task<bool> DeletePostAsync(Guid postToDelete)
        {
            var exists = await GetPostByIdAsync(postToDelete);

            if (exists == null)
                return false;

            _dataContext.Posts.Remove(exists);
            var deleted = await _dataContext.SaveChangesAsync();
            return deleted > 0;
        }


        public async Task<bool> CreatePostAsync(Post post)
        {
            await _dataContext.Posts.AddAsync(post);
            var created = await _dataContext.SaveChangesAsync();
            return created > 0;
        }
    }
}