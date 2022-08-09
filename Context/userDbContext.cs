using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;
using AuthServiceDavivienda.Models;

namespace AuthServiceDavivienda.Context
{
    public partial class userDbContext : DbContext
    {
        public userDbContext()
        {
        }

        public userDbContext(DbContextOptions<userDbContext> options)
            : base(options)
        {
        }

        public virtual DbSet<Employed> Employeds { get; set; } = null!;
        public virtual DbSet<Role> Roles { get; set; } = null!;
        public virtual DbSet<UserRole> UserRoles { get; set; } = null!;
        public virtual DbSet<UserToken> UserTokens { get; set; } = null!;

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            if (!optionsBuilder.IsConfigured)
            {
#warning To protect potentially sensitive information in your connection string, you should move it out of source code. You can avoid scaffolding the connection string by using the Name= syntax to read it from configuration - see https://go.microsoft.com/fwlink/?linkid=2131148. For more guidance on storing connection strings, see http://go.microsoft.com/fwlink/?LinkId=723263.
                optionsBuilder.UseSqlServer("Server=DESKTOP-0M6K0LJ;Initial Catalog=WS_USERS;Integrated Security=True");
            }
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Employed>(entity =>
            {
                entity.HasKey(e => e.Identification);

                entity.ToTable("Employed");

                entity.Property(e => e.Identification)
                    .HasMaxLength(50)
                    .IsUnicode(false)
                    .HasColumnName("identification");

                entity.Property(e => e.CreatedAt)
                    .HasColumnType("datetime")
                    .HasColumnName("created_at")
                    .HasDefaultValueSql("(getdate())");

                entity.Property(e => e.CurrentIp)
                    .HasMaxLength(50)
                    .IsUnicode(false)
                    .HasColumnName("current_ip");

                entity.Property(e => e.Email)
                    .HasMaxLength(50)
                    .IsUnicode(false)
                    .HasColumnName("email");

                entity.Property(e => e.EncryptedPass)
                    .HasMaxLength(1000)
                    .IsUnicode(false)
                    .HasColumnName("encrypted_pass");

                entity.Property(e => e.FirstName)
                    .HasMaxLength(50)
                    .IsUnicode(false)
                    .HasColumnName("first_name");

                entity.Property(e => e.LastName)
                    .HasMaxLength(50)
                    .IsUnicode(false)
                    .HasColumnName("last_name");

                entity.Property(e => e.State).HasColumnName("state");

                entity.Property(e => e.UpdateAt)
                    .HasColumnType("datetime")
                    .HasColumnName("update_at")
                    .HasDefaultValueSql("(getdate())");
            });

            modelBuilder.Entity<Role>(entity =>
            {
                entity.Property(e => e.Id).HasColumnName("id");

                entity.Property(e => e.CreatedAt)
                    .HasColumnType("datetime")
                    .HasColumnName("created_at")
                    .HasDefaultValueSql("(getdate())");

                entity.Property(e => e.Description)
                    .HasMaxLength(50)
                    .IsUnicode(false)
                    .HasColumnName("description");

                entity.Property(e => e.ShortName)
                    .HasMaxLength(50)
                    .IsUnicode(false)
                    .HasColumnName("short_name");

                entity.Property(e => e.UpdatedAt)
                    .HasColumnType("datetime")
                    .HasColumnName("updated_at")
                    .HasDefaultValueSql("(getdate())");
            });

            modelBuilder.Entity<UserRole>(entity =>
            {
                entity.ToTable("User_Roles");

                entity.HasIndex(e => e.UserIdentity, "Unique_User_Roles")
                    .IsUnique();

                entity.Property(e => e.Id)
                    .ValueGeneratedNever()
                    .HasColumnName("id");

                entity.Property(e => e.CreatedAt)
                    .HasColumnType("datetime")
                    .HasColumnName("created_at");

                entity.Property(e => e.RoleId).HasColumnName("role_id");

                entity.Property(e => e.UpdatedAt)
                    .HasColumnType("datetime")
                    .HasColumnName("updated_at");

                entity.Property(e => e.UserIdentity)
                    .HasMaxLength(50)
                    .IsUnicode(false)
                    .HasColumnName("user_identity")
                    .HasDefaultValueSql("(getdate())");
            });

            modelBuilder.Entity<UserToken>(entity =>
            {
                entity.ToTable("User_Token");

                entity.HasIndex(e => e.UserIdentity, "Unique_User_Token")
                    .IsUnique();

                entity.Property(e => e.Id).HasColumnName("id");

                entity.Property(e => e.CurrentToken)
                    .HasColumnType("datetime")
                    .HasColumnName("current_token")
                    .HasDefaultValueSql("(getdate())");

                entity.Property(e => e.HashToken)
                    .HasMaxLength(1000)
                    .IsUnicode(false)
                    .HasColumnName("hash_token");

                entity.Property(e => e.LastToken)
                    .HasColumnType("datetime")
                    .HasColumnName("last_token")
                    .HasDefaultValueSql("(getdate())");

                entity.Property(e => e.UserIdentity)
                    .HasMaxLength(50)
                    .IsUnicode(false)
                    .HasColumnName("user_identity");
            });

            OnModelCreatingPartial(modelBuilder);
        }

        partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
    }
}
