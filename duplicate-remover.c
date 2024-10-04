// Made By Jay @ J~Net 2024
// gcc -o duplicate-remover duplicate-remover.c `pkg-config --cflags --libs gtk+-3.0 openssl`
//

#include <gtk/gtk.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#define BUFFER_SIZE 4096
#define MAX_FILE_TYPE_LENGTH 20

// Function to calculate the MD5 hash of a file
void calculate_md5(const char *filename, unsigned char *md) {
    unsigned char buffer[BUFFER_SIZE];
    size_t bytesRead;
    EVP_MD_CTX *mdContext;
    const EVP_MD *md5;
    FILE *file;

    file=fopen(filename, "rb");
    if (!file) {
        perror("Unable to open file");
        return;
    }

    mdContext=EVP_MD_CTX_new();
    md5=EVP_md5();

    if (EVP_DigestInit_ex(mdContext, md5, NULL) != 1) {
        fprintf(stderr, "EVP_DigestInit_ex failed\n");
        fclose(file);
        EVP_MD_CTX_free(mdContext);
        return;
    }

    while ((bytesRead=fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        if (EVP_DigestUpdate(mdContext, buffer, bytesRead) != 1) {
            fprintf(stderr, "EVP_DigestUpdate failed\n");
            fclose(file);
            EVP_MD_CTX_free(mdContext);
            return;
        }
    }

    if (EVP_DigestFinal_ex(mdContext, md, NULL) != 1) {
        fprintf(stderr, "EVP_DigestFinal_ex failed\n");
    }

    fclose(file);
    EVP_MD_CTX_free(mdContext);
}

// Global variables for UI components
GtkWidget *auto_remove_check, *recursive_check, *file_type_entry;
GtkListStore *directory_store;

// Function to add a directory to the list
void add_directory(GtkButton *button, gpointer user_data) {
    GtkWidget *dialog=gtk_file_chooser_dialog_new("Select Directory", GTK_WINDOW(user_data),
                                                    GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER,
                                                    "Cancel", GTK_RESPONSE_CANCEL,
                                                    "Select", GTK_RESPONSE_ACCEPT, NULL);

    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        char *directory=gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        GtkTreeIter iter;
        gtk_list_store_append(directory_store, &iter);
        gtk_list_store_set(directory_store, &iter, 0, directory, -1);
        g_free(directory);
    }

    gtk_widget_destroy(dialog);
}

// Function to check file extension against the specified filter
gboolean file_extension_matches(const char *filename, const char *filter) {
    if (strcmp(filter, "*.*") == 0) return TRUE; // All files

    const char *ext=strrchr(filename, '.');
    if (!ext) return FALSE; // No extension found

    return strcmp(ext, filter) == 0; // Match the filter
}

// Function to remove duplicates
void remove_duplicates(const char *directory, gboolean recursive, gboolean auto_remove, const char *filter, GHashTable *hash_table) {
    DIR *dir;
    struct dirent *entry;
    char path[PATH_MAX];

    if (!(dir=opendir(directory)))
        return;

    while ((entry=readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            if (recursive && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name);
                remove_duplicates(path, recursive, auto_remove, filter, hash_table);
            }
        } else {
            snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name);
            if (!file_extension_matches(path, filter)) continue; // Skip files not matching the filter

            unsigned char md[EVP_MAX_MD_SIZE];
            calculate_md5(path, md);
            char md5_string[33];
            for (int i=0; i < 16; i++) {
                snprintf(&md5_string[i * 2], 3, "%02x", md[i]);
            }

            if (g_hash_table_contains(hash_table, md5_string)) {
                printf("Duplicate found: %s\n", path);
                if (auto_remove) {
                    printf("Removing duplicate: %s\n", path);
                    remove(path);
                }
            } else {
                g_hash_table_insert(hash_table, g_strdup(md5_string), g_strdup(path));
            }
        }
    }

    closedir(dir);
}

// Function to start scanning for duplicates
void start_scan(GtkButton *button, gpointer user_data) {
    gboolean recursive=gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(recursive_check));
    gboolean auto_remove=gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(auto_remove_check));
    const gchar *filter=gtk_entry_get_text(GTK_ENTRY(file_type_entry));

    GHashTable *hash_table=g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

    GtkTreeIter iter;
    gboolean valid=gtk_tree_model_get_iter_first(GTK_TREE_MODEL(directory_store), &iter);
    while (valid) {
        gchar *directory;
        gtk_tree_model_get(GTK_TREE_MODEL(directory_store), &iter, 0, &directory, -1);
        remove_duplicates(directory, recursive, auto_remove, filter, hash_table);
        g_free(directory);
        valid=gtk_tree_model_iter_next(GTK_TREE_MODEL(directory_store), &iter);
    }

    g_hash_table_destroy(hash_table);
    gtk_label_set_text(GTK_LABEL(user_data), "Scan complete");
}

// Function to display the "About" dialog
void show_about(GtkButton *button, gpointer user_data) {
    GtkWidget *dialog=gtk_message_dialog_new(GTK_WINDOW(user_data),
                                               GTK_DIALOG_DESTROY_WITH_PARENT,
                                               GTK_MESSAGE_INFO,
                                               GTK_BUTTONS_OK,
                                               "Duplicate Remover\nAuthor: Jay Mee @ J~Net 2024");
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

// Function to create the main window
GtkWidget* create_window() {
    GtkWidget *window, *vbox, *hbox, *scrolled_window, *tree_view, *button, *status_label;

    window=gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "Duplicate File Remover");
    gtk_container_set_border_width(GTK_CONTAINER(window), 10);
    gtk_widget_set_size_request(window, 400, 300);

    vbox=gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_container_add(GTK_CONTAINER(window), vbox);

    auto_remove_check=gtk_check_button_new_with_label("Auto Remove Duplicates");
    gtk_box_pack_start(GTK_BOX(vbox), auto_remove_check, FALSE, FALSE, 0);

    recursive_check=gtk_check_button_new_with_label("Recursive Scan");
    gtk_box_pack_start(GTK_BOX(vbox), recursive_check, FALSE, FALSE, 0);

    // File type entry
    file_type_entry=gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(file_type_entry), "*.*"); // Default value
    gtk_box_pack_start(GTK_BOX(vbox), file_type_entry, FALSE, FALSE, 0);

    scrolled_window=gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_box_pack_start(GTK_BOX(vbox), scrolled_window, TRUE, TRUE, 0);

    directory_store=gtk_list_store_new(1, G_TYPE_STRING);
    tree_view=gtk_tree_view_new_with_model(GTK_TREE_MODEL(directory_store));
    GtkCellRenderer *renderer=gtk_cell_renderer_text_new();
    GtkTreeViewColumn *column=gtk_tree_view_column_new_with_attributes("Directories", renderer, "text", 0, NULL);
    gtk_tree_view_append_column(GTK_TREE_VIEW(tree_view), column);
    gtk_container_add(GTK_CONTAINER(scrolled_window), tree_view);

    hbox=gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);

    button=gtk_button_new_with_label("Add Directory");
    g_signal_connect(button, "clicked", G_CALLBACK(add_directory), window);
    gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);

    button=gtk_button_new_with_label("Start Scan");
    status_label=gtk_label_new("Ready");
    g_signal_connect(button, "clicked", G_CALLBACK(start_scan), status_label);
    gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);

    button=gtk_button_new_with_label("About");
    g_signal_connect(button, "clicked", G_CALLBACK(show_about), window);
    gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);

    gtk_box_pack_start(GTK_BOX(vbox), status_label, FALSE, FALSE, 0);

    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
    return window;
}

// Function to display help information
void show_help() {
    printf("Usage: duplicate-remover [options]\n");
    printf("Options:\n");
    printf("  -d, --directory <path>   Specify the directory to scan\n");
    printf("  -f, --filetype <type>     Specify the file type to filter (default: *.*)\n");
    printf("  -r, --recursive           Perform a recursive scan\n");
    printf("  -a, --auto-remove         Automatically remove duplicates\n");
    printf("  -h, --help                Display this help message\n");
}

int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);

    // Command-line argument processing
    const char *directory=NULL;
    const char *file_type="*.*"; // Default filter
    gboolean recursive=FALSE;
    gboolean auto_remove=FALSE;

    for (int i=1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            show_help();
            return 0;
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--directory") == 0) {
            if (i + 1 < argc) {
                directory=argv[++i];
            }
        } else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--filetype") == 0) {
            if (i + 1 < argc) {
                file_type=argv[++i];
            }
        } else if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--recursive") == 0) {
            recursive=TRUE;
        } else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--auto-remove") == 0) {
            auto_remove=TRUE;
        }
    }

    GtkWidget *window=create_window();
    gtk_widget_show_all(window);

    // If a directory is provided via command-line, add it to the list
    if (directory) {
        GtkTreeIter iter;
        gtk_list_store_append(directory_store, &iter);
        gtk_list_store_set(directory_store, &iter, 0, directory, -1);
    }

    gtk_main();
    return 0;
}

