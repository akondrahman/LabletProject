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

# THE_FILE    <- "/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/RESULTS/FSE2020/OPENSTACK_YEAR_TEMPORAL.csv"
# THE_LIMIT   <- 1
# THE_DS_NAME <- "OPENSTACK"
# OUT_FIL     <- "/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/FSE-Writing/FSE20_Vuln_Tactic/images/OPENSTACK_YEAR.pdf"

# THE_FILE    <- "/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/RESULTS/FSE2020/PHP_YEAR_TEMPORAL.csv"
# THE_LIMIT   <- 1
# THE_DS_NAME <- "PHP"
# OUT_FIL     <- "/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/FSE-Writing/FSE20_Vuln_Tactic/images/PHP_YEAR.pdf"

### ======================================================================================== ###

Y_LABEL     <- "Strategy/Year(%)"
FONT_SIZE   <- 16

BAR_DATA <- read.csv(THE_FILE)
BAR_DATA$YEAR <- as.factor(BAR_DATA$YEAR)
colnames(BAR_DATA)[colnames(BAR_DATA) == 'TACTIC_NAME'] <- 'STRATEGY'
print(head(BAR_DATA))


pdf(OUT_FIL, width=8, height=4)


the_plot <- ggplot(data=BAR_DATA, aes(x=YEAR, y=TACTIC_PERC, fill=STRATEGY)) + geom_bar(stat="identity", color="black", position=position_dodge(), width=0.5) +
            labs(x='Year', y=Y_LABEL)  +
            theme(text = element_text(size=FONT_SIZE), axis.text.x = element_text(angle=45, hjust=1, size=FONT_SIZE), axis.text.y = element_text(size=FONT_SIZE), axis.title=element_text(size=FONT_SIZE, face="bold")) +
            ggtitle(THE_DS_NAME) + theme(plot.title = element_text(hjust = 0.5)) + 
            theme(legend.position="bottom")

the_plot

dev.off()

t2 <- Sys.time()
print(t2 - t1)  
rm(list = setdiff(ls(), lsf.str()))