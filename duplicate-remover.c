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
GtkWidget *auto_remove_check, *recursive_check;
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

// Function to remove duplicates
void remove_duplicates(const char *directory, gboolean recursive, gboolean auto_remove, GHashTable *hash_table) {
    DIR *dir;
    struct dirent *entry;
    char path[PATH_MAX];

    if (!(dir=opendir(directory)))
        return;

    while ((entry=readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            if (recursive && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name);
                remove_duplicates(path, recursive, auto_remove, hash_table);
            }
        } else {
            snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name);
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

typedef struct {
    GHashTable *hash_table;
    gboolean recursive;
    gboolean auto_remove;
    GtkTreeIter iter;
    GtkTreeModel *model;
    GtkWidget *status_label;
} ScanData;

gboolean process_directory(gpointer user_data) {
    ScanData *data = (ScanData *)user_data;
    gchar *directory;

    if (!gtk_tree_model_get_iter_first(GTK_TREE_MODEL(data->model), &data->iter)) {
        gtk_label_set_text(GTK_LABEL(data->status_label), "Scan complete");
        g_hash_table_destroy(data->hash_table);
        g_free(data);
        return FALSE; // Stop the idle function
    }

    do {
        gtk_tree_model_get(GTK_TREE_MODEL(data->model), &data->iter, 0, &directory, -1);
        remove_duplicates(directory, data->recursive, data->auto_remove, data->hash_table);
        g_free(directory);
    } while (gtk_tree_model_iter_next(GTK_TREE_MODEL(data->model), &data->iter));

    gtk_label_set_text(GTK_LABEL(data->status_label), "Scan complete");
    g_hash_table_destroy(data->hash_table);
    g_free(data);
    return FALSE; // Stop the idle function
}

// Function to start scanning for duplicates
void start_scan(GtkButton *button, gpointer user_data) {
    gboolean recursive = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(recursive_check));
    gboolean auto_remove = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(auto_remove_check));

    GHashTable *hash_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

    ScanData *data = g_malloc(sizeof(ScanData));
    data->hash_table = hash_table;
    data->recursive = recursive;
    data->auto_remove = auto_remove;
    data->model = GTK_TREE_MODEL(directory_store);
    data->status_label = GTK_WIDGET(user_data);

    gtk_label_set_text(GTK_LABEL(user_data), "Scanning...");
    g_idle_add(process_directory, data); // Process the directories incrementally
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
    GtkCellRenderer *renderer;
    GtkTreeViewColumn *column;

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

    scrolled_window=gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_box_pack_start(GTK_BOX(vbox), scrolled_window, TRUE, TRUE, 0);

    directory_store=gtk_list_store_new(1, G_TYPE_STRING);
    tree_view=gtk_tree_view_new_with_model(GTK_TREE_MODEL(directory_store));
    renderer=gtk_cell_renderer_text_new();
    column=gtk_tree_view_column_new_with_attributes("Directories", renderer, "text", 0, NULL);
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

    return window;
}

int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);

    GtkWidget *window=create_window();

    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
    gtk_widget_show_all(window);

    gtk_main();

    return 0;
}

