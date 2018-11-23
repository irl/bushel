
library("ggplot2")
library("RColorBrewer")
library("scales")
library(dplyr)
library(tidyr)
library(readr)

theme_update(
  # Make plot title centered, and leave some room to the plot.
  plot.title = element_text(hjust = 0.5, margin = margin(b = 11)),

  # Leave a little more room to the right for long x axis labels.
  plot.margin = margin(5.5, 11, 5.5, 5.5)
)

# Set the default line size of geom_line() to 1.
update_geom_defaults("line", list(size = 1))

copyright_notice <- "The Tor Project - https://metrics.torproject.org/"

prepare_stats <- function() {
  read_csv("stats.csv",
    col_names=c("valid_after", "server_referenced", "server_descriptor",
                "directory_cache", "directory_cache_dir_port",
                "extra_info_cache", "extra_info_cache_dir_port", "extra_info_referenced", "extra_info_descriptor")) %>%
    filter(server_descriptor/server_referenced > 0.9) %>%
    mutate(adjusted_directory_cache = (directory_cache/server_descriptor) * server_referenced) %>%
    mutate(adjusted_directory_cache_dir_port = (directory_cache_dir_port/server_descriptor) * server_referenced) %>%
    mutate(adjusted_extra_info_cache = (extra_info_cache/server_descriptor) * server_referenced) %>%
    mutate(adjusted_extra_info_cache_dir_port = (extra_info_cache_dir_port/server_descriptor) * server_referenced)
}

plot_directory_servers <- function() {
  prepare_stats() %>%
    gather(variable, value, -valid_after) %>%
    complete(valid_after = valid_after,
             variable = c("adjusted_directory_cache", "adjusted_directory_cache_dir_port", "adjusted_extra_info_cache", "adjusted_extra_info_cache_dir_port")) %>%
    ggplot(aes(x = valid_after, y = value, color = variable)) +
    geom_line() +
    scale_x_datetime(name = "Consensus valid-after Time") +
    scale_y_log10(name = "Servers (log scale)", breaks = c(50, 100, 200, 500, 1000, 2000, 5000)) +
    scale_colour_hue("", breaks = c("adjusted_directory_cache", "adjusted_directory_cache_dir_port", "adjusted_extra_info_cache", "adjusted_extra_info_cache_dir_port"),
        labels = c("All", "... with DirPort", "Extra-info cache", "... with DirPort")) +
    ggtitle("Directory servers seen in network status consensuses") +
    #labs(caption = copyright_notice)
  ggsave(filename = "directory_servers.pdf", width = 8, height = 5, dpi = 150)
}

plot_directory_servers()

plot_extra_info_caches <- function() {
  prepare_stats() %>%
    gather(variable, value, -valid_after) %>%
    complete(valid_after = valid_after,
             variable = c("adjusted_extra_info_cache", "adjusted_extra_info_cache_dir_port")) %>%
    ggplot(aes(x = valid_after, y = value, color = variable)) +
    geom_line() +
    scale_x_datetime(name = "Consensus valid-after Time") +
    scale_y_continuous(name = "Servers", limits = c(0, NA)) +
    scale_colour_hue("", breaks = c("adjusted_extra_info_cache", "adjusted_extra_info_cache_dir_port"),
        labels = c("All", "with DirPort")) +
    ggtitle("Extra-info caches seen in network status consensuses") +
    #labs(caption = copyright_notice)
  ggsave(filename = "extra_info_caches.pdf", width = 8, height = 5, dpi = 150)
}

plot_extra_info_caches()

