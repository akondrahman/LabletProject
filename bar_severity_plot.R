cat("\014") 
options(max.print=1000000)
t1 <- Sys.time()
library(ggplot2)

# THE_FILE    <- "/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/RESULTS/FSE2020/CHROME_PLOTDATA_SEVERITY.csv"
# THE_LIMIT   <- 1
# THE_DS_NAME <- "CHROME"
# OUT_FIL     <- "/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/FSE-Writing/FSE20_Vuln_Tactic/images/CHROME_SEVERITY.pdf"

# THE_FILE    <- "/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/RESULTS/FSE2020/ECLIPSE_PLOTDATA_SEVERITY.csv"
# THE_LIMIT   <- 1
# THE_DS_NAME <- "ECLIPSE"
# OUT_FIL     <- "/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/FSE-Writing/FSE20_Vuln_Tactic/images/ECLIPSE_SEVERITY.pdf"

# THE_FILE    <- "/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/RESULTS/FSE2020/MOBY_PLOTDATA_SEVERITY.csv"
# THE_LIMIT   <- 1
# THE_DS_NAME <- "MOBY"
# OUT_FIL     <- "/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/FSE-Writing/FSE20_Vuln_Tactic/images/MOBY_SEVERITY.pdf"

# THE_FILE    <- "/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/RESULTS/FSE2020/MOZILLA_PLOTDATA_SEVERITY.csv"
# THE_LIMIT   <- 1
# THE_DS_NAME <- "MOZILLA"
# OUT_FIL     <- "/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/FSE-Writing/FSE20_Vuln_Tactic/images/MOZILLA_SEVERITY.pdf"

# THE_FILE    <- "/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/RESULTS/FSE2020/OPENSTACK_PLOTDATA_SEVERITY.csv"
# THE_LIMIT   <- 1
# THE_DS_NAME <- "OPENSTACK"
# OUT_FIL     <- "/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/FSE-Writing/FSE20_Vuln_Tactic/images/OPENSTACK_SEVERITY.pdf"

# THE_FILE    <- "/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/RESULTS/FSE2020/PHP_PLOTDATA_SEVERITY.csv"
# THE_LIMIT   <- 1
# THE_DS_NAME <- "PHP"
# OUT_FIL     <- "/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/FSE-Writing/FSE20_Vuln_Tactic/images/PHP_SEVERITY.pdf"

### ======================================================================================== ###

Y_LABEL     <- "PropVuln(%)"
FONT_SIZE   <- 16

BAR_DATA <- read.csv(THE_FILE)
BAR_DATA$SEVERITY <- as.factor(BAR_DATA$SEVERITY)
BAR_DATA$SEVERITY <- factor(BAR_DATA$SEVERITY, levels = c("CRITICAL", "HIGH", "MEDIUM", "LOW"))
print(head(BAR_DATA))


pdf(OUT_FIL, width=8, height=4)


the_plot <- ggplot(data=BAR_DATA, aes(x=SEVERITY, y=PERC_PER_STRATEGY, fill=STRATEGY)) + geom_bar(stat="identity", color="black", position=position_dodge(), width=0.5) +
  labs(x='Severity', y=Y_LABEL)  +
  theme(text = element_text(size=FONT_SIZE), axis.text.x = element_text(angle=45, hjust=1, size=FONT_SIZE), axis.text.y = element_text(size=FONT_SIZE), axis.title=element_text(size=FONT_SIZE, face="bold")) +
  ggtitle(THE_DS_NAME) + theme(plot.title = element_text(hjust = 0.5)) + 
  theme(legend.position="bottom")

the_plot

dev.off()

t2 <- Sys.time()
print(t2 - t1)  
rm(list = setdiff(ls(), lsf.str()))