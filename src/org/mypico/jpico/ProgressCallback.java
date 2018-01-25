package org.mypico.jpico;

/**
 * A callback interface to receive feedback from the authentication process.
 *
 * @author Seb Aebischer &lt;seb.aebischer@cl.cam.ac.uk&gt;
 */

public interface ProgressCallback {

    /**
     * A stage in the authentication process. This tells you which stage out of how many the process
     * is currently in.
     * <p>
     * To get values suitable for use with a progress bar (i.e. current progress and maximum), use
     * {@link #getProgress()} and {@link #getMaxProgress()}. This is subtly different to using the
     * {@link #stage} value directly in that it starts from 0 instead of 1, since, at the time of
     * starting the first stage, no progress has yet been made.
     */
    class Stage {
        /**
         * The stage number. For the first stage this has value {@code 0}. To get overall progress,
         * use {@link #getProgressFraction()}.
         */
        private final int stage;
        /**
         * The total number of stages in the process
         */
        private final int stages;
        /**
         * A short hard-coded description of what is going on in this stage
         */
        private final String description;

        public Stage(int stage, int stages, String description) {
            if (stage < 0)
                throw new IllegalArgumentException();
            this.stage = stage;
            this.stages = stages;
            this.description = description;
        }

        @Override
        public String toString() {
            return "Stage " + stage + " of " + stages + ": " + description;
        }

        /**
         * Convenience function to calculate overall progress. The first stage will give a value of
         * 0, meaning no progress has yet been made, while the final stage returns a value of 1,
         * meaning "finished".
         *
         * @return The progress as a value between 0 and 1.
         */
        public float getProgressFraction() {
            return getProgress() / (float) getMaxProgress();
        }

        /**
         * @return The current progress, suitable for setting a progress bar. Use
         * {@link #getMaxProgress()} to get the maximum value.
         */
        public int getProgress() {
            return stage;
        }

        /**
         * @return The maximum value {@link #getProgress()} will return.
         */
        public int getMaxProgress() {
            return stages - 1;
        }

        /**
         * @return A description of the this stage.
         */
        public String getDescription() {
            return description;
        }

    }

    /**
     * Called when the process enters a stage.
     *
     * @param caller       The calling object, to provide some context. Typically this will be a
     *                     {@link org.mypico.jpico.crypto.NewSigmaProver}.
     * @param currentStage The {@link Stage} that just started.
     */
    void onAuthProgress(Object caller, Stage currentStage);

}
