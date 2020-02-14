cat("\014") 
options(max.print=1000000)
t1 <- Sys.time()
library(ggplot2)
library(likert)

THE_FILE <- "/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/VERIFIABILITY_PACKAGE/FULL_SURVEY_DATA.csv"
SURVEY_DATA  <- read.csv(THE_FILE)

print('==========')
print('STAS FOR SWE EXP')
print( summary(SURVEY_DATA$SWE_EXP) )
print('==========')
print('STAS FOR VUL EXP')
print( summary(SURVEY_DATA$VUL_EXP) )
print('==========')



SURVEY_DATA  <- SURVEY_DATA[ -c(1, 2, 3, 8) ]
							
names(SURVEY_DATA) = c("DIAGNOSTICS",	"EXECUTION", "MISCONFIG",	"PAYLOAD")

mylevels <- c('Strongly disagree', 'Disagree', 'Neutral', 'Agree', 'Strongly agree')

for(i in seq_along(SURVEY_DATA)) {
  SURVEY_DATA[, i] <- factor(SURVEY_DATA[, i], levels=mylevels)
}

title_ <- "Practitioner Perception on Identified Vulnerability Discovery Strategies" 

LIKERT_DATA <- likert(SURVEY_DATA)
print(LIKERT_DATA)


pdf('/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/VulnStrategyMining/FSE-Writing/FSE20_Vuln_Tactic/images/SURVEY_RES.pdf', width=9.8, height=3.5)

the_plot <- plot(LIKERT_DATA, ordered=TRUE, group.order=names(SURVEY_DATA), colors=c('darkred','pink','yellow','greenyellow','darkgreen'), centered = FALSE, include.histogram = FALSE, legend.position = "bottom", text.size = 6) 
the_plot <- the_plot + theme( plot.title = element_text(size = 12, face = "bold"), legend.title=element_text(size=12), legend.text=element_text(size=12))
the_plot <- the_plot + theme(axis.text.y = element_text(hjust=0.5, size = 18)) + theme(axis.text.x = element_text(size = 18)) 

the_plot

dev.off()

t2 <- Sys.time()
print(t2 - t1)  
rm(list = setdiff(ls(), lsf.str()))