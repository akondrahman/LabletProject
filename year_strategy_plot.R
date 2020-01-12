cat("\014") 
options(max.print=1000000)
t1 <- Sys.time()
library(ggplot2)

# THE_FILE    <- "/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/RESULTS/FSE2020/CHROME_YEAR_TEMPORAL.csv"
# THE_LIMIT   <- 1
# THE_DS_NAME <- "CHROME"
# OUT_FIL     <- "/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/FSE-Writing/FSE20_Vuln_Tactic/images/CHROME_YEAR.pdf"


# THE_FILE    <- "/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/RESULTS/FSE2020/ECLIPSE_YEAR_TEMPORAL.csv"
# THE_LIMIT   <- 1
# THE_DS_NAME <- "ECLIPSE"
# OUT_FIL     <- "/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/FSE-Writing/FSE20_Vuln_Tactic/images/ECLIPSE_YEAR.pdf"

# THE_FILE    <- "/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/RESULTS/FSE2020/MOBY_YEAR_TEMPORAL.csv"
# THE_LIMIT   <- 1
# THE_DS_NAME <- "MOBY"
# OUT_FIL     <- "/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/FSE-Writing/FSE20_Vuln_Tactic/images/MOBY_YEAR.pdf"

# THE_FILE    <- "/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/RESULTS/FSE2020/MOZILLA_YEAR_TEMPORAL.csv"
# THE_LIMIT   <- 1
# THE_DS_NAME <- "MOZILLA"
# OUT_FIL     <- "/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/FSE-Writing/FSE20_Vuln_Tactic/images/MOZILLA_YEAR.pdf"


### ======================================================================================== ###

Y_LABEL     <- "Strategy/Year(%)"

LINE_DATA <- read.csv(THE_FILE)
LINE_DATA$YEAR <- as.factor(LINE_DATA$YEAR)
print(head(LINE_DATA))


pdf(OUT_FIL, width=8, height=1.6)

the_plot  <- ggplot(data=LINE_DATA, aes(x=YEAR, y=TACTIC_PERC, group=1)) + 
  geom_point(size=0.1) +  scale_x_discrete(breaks = LINE_DATA$YEAR[seq(1, length(LINE_DATA$YEAR), by = THE_LIMIT)]) + 
  geom_smooth(size=0.5, aes(color=TACTIC_NAME), method='loess') +   
  facet_grid( . ~ TACTIC_NAME) +
  labs(x='Year', y=Y_LABEL) +
  theme(text = element_text(size=9), axis.text.x = element_text(angle=45, hjust=1, size=9), axis.text.y = element_text(size=9), axis.title=element_text(size=9, face="bold")) +
  ggtitle(THE_DS_NAME) + theme(plot.title = element_text(hjust = 0.5)) + 
  theme(legend.position="none")   

the_plot

dev.off()

t2 <- Sys.time()
print(t2 - t1)  
rm(list = setdiff(ls(), lsf.str()))