#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
// gcc -o zipper zipper.c `pkg-config --cflags --libs gtk+-3.0`

#define MAX_FILES 100
#define MAX_PATH 1024

static char *file_paths[MAX_FILES];
static int file_count=0;
GtkWidget *file_list;
GtkWidget *check_recursive;
GtkWidget *check_relative_paths;
GtkWidget *check_test_archive;
GtkWidget *entry_password;

void show_message(const char *message) {
    GtkWidget *dialog=gtk_message_dialog_new(NULL, GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_INFO, GTK_BUTTONS_OK, "%s", message);
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

char *get_parent_folder_name(const char *path) {
    char *folder=strrchr(path, '/');
    if (folder) {
        *folder='\0';
        return strdup(path);
    }
    return NULL;
}

char *get_relative_paths(char *file_paths[]) {
    char *result=malloc(MAX_PATH * MAX_FILES);
    result[0]='\0'; // Initialize as empty string
    for (int i=0; i < file_count; i++) {
        char relative_path[MAX_PATH];
        realpath(file_paths[i], relative_path); // Get absolute path
        snprintf(result + strlen(result), MAX_PATH * MAX_FILES - strlen(result), " %s", relative_path); // Append to result
    }
    return result;
}

char *get_full_paths(char *file_paths[]) {
    char *result=malloc(MAX_PATH * MAX_FILES);
    result[0]='\0'; // Initialize as empty string
    for (int i=0; i < file_count; i++) {
        snprintf(result + strlen(result), MAX_PATH * MAX_FILES - strlen(result), " %s", file_paths[i]); // Append to result
    }
    return result;
}

int compare_files_with_extracted(char *original_files[], const char *extracted_folder) {
    for (int i=0; i < file_count; i++) {
        char extracted_path[MAX_PATH];
        snprintf(extracted_path, sizeof(extracted_path), "%s/%s", extracted_folder, strrchr(original_files[i], '/') + 1);
        
        struct stat orig_stat, ext_stat;
        if (stat(original_files[i], &orig_stat) != 0 || stat(extracted_path, &ext_stat) != 0) {
            return 0; // If either file doesn't exist, return false
        }
        
        // Compare sizes and modification times
        if (orig_stat.st_size != ext_stat.st_size || orig_stat.st_mtime != ext_stat.st_mtime) {
            return 0; // Files do not match
        }
    }
    return 1; // All files matched
}

void on_add_files(GtkWidget *widget, gpointer data) {
    GtkWidget *dialog=gtk_file_chooser_dialog_new("Select Files", NULL, GTK_FILE_CHOOSER_ACTION_OPEN, "_Cancel", GTK_RESPONSE_CANCEL, "_Open", GTK_RESPONSE_ACCEPT, NULL);
    gtk_file_chooser_set_select_multiple(GTK_FILE_CHOOSER(dialog), TRUE);

    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        GSList *files=gtk_file_chooser_get_filenames(GTK_FILE_CHOOSER(dialog));
        for (GSList *iter=files; iter != NULL; iter=iter->next) {
            if (file_count < MAX_FILES) {
                file_paths[file_count++]=g_strdup(iter->data);
                gtk_list_store_insert_with_values(GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(file_list))), NULL, file_count - 1, 0, iter->data, -1);
            }
            g_free(iter->data);
        }
        g_slist_free(files);
    }

    gtk_widget_destroy(dialog);
}

void on_remove_selected(GtkWidget *widget, gpointer data) {
    GtkTreeSelection *selection=gtk_tree_view_get_selection(GTK_TREE_VIEW(file_list));
    GtkTreeModel *model;
    GtkTreeIter iter;

    if (gtk_tree_selection_get_selected(selection, &model, &iter)) {
        gchar *file_path;
        gtk_tree_model_get(model, &iter, 0, &file_path, -1);
        gtk_list_store_remove(GTK_LIST_STORE(model), &iter);

        for (int i=0; i < file_count; i++) {
            if (g_strcmp0(file_paths[i], file_path) == 0) {
                g_free(file_paths[i]);
                file_paths[i]=file_paths[--file_count]; // Move the last element to the removed spot
                break;
            }
        }

        g_free(file_path);
    }
}

void on_create_archive(GtkWidget *widget, gpointer data) {
    if (file_count == 0) {
        show_message("Please add a file or folder first.");
        return;
    }

    char zip_filename[MAX_PATH];
    snprintf(zip_filename, sizeof(zip_filename), "%s.zip", get_parent_folder_name(file_paths[0]));

    const char *password=gtk_entry_get_text(GTK_ENTRY(entry_password));

    char *zip_paths=gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(check_relative_paths)) ? get_relative_paths(file_paths) : get_full_paths(file_paths);
    size_t command_size=snprintf(NULL, 0, "zip -r%s %s %s%s", 
        (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(check_recursive)) ? "" : " -j "), 
        zip_filename, 
        zip_paths, 
        (strlen(password) > 0) ? g_strdup_printf(" -P %s", password) : "") + 1;

    char *command=malloc(command_size);
    if (!command) {
        show_message("Memory allocation failed.");
        return;
    }

    snprintf(command, command_size, "zip -r%s %s %s%s", 
        (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(check_recursive)) ? "" : " -j "), 
        zip_filename, 
        zip_paths, 
        (strlen(password) > 0) ? g_strdup_printf(" -P %s", password) : "");

    int ret=system(command);
    
    if (ret != 0) {
        show_message("Archive creation encountered an issue. Check if files are added.");
    } else {
        show_message("Archive created successfully.");
    }

    // Check if the user wants to test the archive
    if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(check_test_archive))) {
        char extract_command[MAX_PATH + 50];
        snprintf(extract_command, sizeof(extract_command), "unzip -q -d temp_extract %s", zip_filename);
        system(extract_command);

        if (compare_files_with_extracted(file_paths, "temp_extract")) {
            show_message("Archive tested successfully.");
        } else {
            show_message("Archive testing failed. The contents do not match.");
        }

        system("rm -rf temp_extract");
    }

    free(zip_paths);
    free(command);
}

void on_extract_archive(GtkWidget *widget, gpointer data) {
    GtkWidget *dialog=gtk_file_chooser_dialog_new("Select Archive to Extract", NULL, GTK_FILE_CHOOSER_ACTION_OPEN, "_Cancel", GTK_RESPONSE_CANCEL, "_Open", GTK_RESPONSE_ACCEPT, NULL);
    
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        char *archive_path=gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        char extract_command[MAX_PATH + 50];
        
        snprintf(extract_command, sizeof(extract_command), "unzip -q %s -d .", archive_path);
        int ret=system(extract_command);
        
        if (ret == 0) {
            show_message("Archive extracted successfully.");
        } else {
            show_message("Failed to extract the archive.");
        }
        
        g_free(archive_path);
    }

    gtk_widget_destroy(dialog);
}

void on_about(GtkWidget *widget, gpointer data) {
    GtkWidget *dialog=gtk_message_dialog_new(NULL, GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_INFO, GTK_BUTTONS_OK, "Author: Jay Mee @ J~Net 2024");
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);

    GtkWidget *window=gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "Zipper");
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    GtkWidget *vbox=gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_container_add(GTK_CONTAINER(window), vbox);

    file_list=gtk_tree_view_new();
    GtkListStore *store=gtk_list_store_new(1, G_TYPE_STRING);
    gtk_tree_view_set_model(GTK_TREE_VIEW(file_list), GTK_TREE_MODEL(store));
    
    GtkCellRenderer *renderer=gtk_cell_renderer_text_new();
    gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(file_list), -1, "Files", renderer, "text", 0, NULL);

    gtk_box_pack_start(GTK_BOX(vbox), file_list, TRUE, TRUE, 0);

    GtkWidget *btn_add_files=gtk_button_new_with_label("Add Files/Folder");
    g_signal_connect(btn_add_files, "clicked", G_CALLBACK(on_add_files), NULL);
    gtk_box_pack_start(GTK_BOX(vbox), btn_add_files, FALSE, FALSE, 0);

    GtkWidget *btn_remove_selected=gtk_button_new_with_label("Remove Selected");
    g_signal_connect(btn_remove_selected, "clicked", G_CALLBACK(on_remove_selected), NULL);
    gtk_box_pack_start(GTK_BOX(vbox), btn_remove_selected, FALSE, FALSE, 0);

    check_recursive=gtk_check_button_new_with_label("Include Files in Subdirectories");
    gtk_box_pack_start(GTK_BOX(vbox), check_recursive, FALSE, FALSE, 0);

    check_relative_paths=gtk_check_button_new_with_label("Use Relative Paths");
    gtk_box_pack_start(GTK_BOX(vbox), check_relative_paths, FALSE, FALSE, 0);

    check_test_archive=gtk_check_button_new_with_label("Test Archive After Creation");
    gtk_box_pack_start(GTK_BOX(vbox), check_test_archive, FALSE, FALSE, 0);

    entry_password=gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry_password), "Password (optional)");
    gtk_box_pack_start(GTK_BOX(vbox), entry_password, FALSE, FALSE, 0);

    GtkWidget *btn_create_archive=gtk_button_new_with_label("Create Archive");
    g_signal_connect(btn_create_archive, "clicked", G_CALLBACK(on_create_archive), NULL);
    gtk_box_pack_start(GTK_BOX(vbox), btn_create_archive, FALSE, FALSE, 0);

    GtkWidget *btn_extract_archive=gtk_button_new_with_label("Extract Archive");
    g_signal_connect(btn_extract_archive, "clicked", G_CALLBACK(on_extract_archive), NULL);
    gtk_box_pack_start(GTK_BOX(vbox), btn_extract_archive, FALSE, FALSE, 0);

    GtkWidget *btn_about=gtk_button_new_with_label("About");
    g_signal_connect(btn_about, "clicked", G_CALLBACK(on_about), NULL);
    gtk_box_pack_start(GTK_BOX(vbox), btn_about, FALSE, FALSE, 0);

    gtk_widget_show_all(window);
    gtk_main();

    return 0;
}

