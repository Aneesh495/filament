# =============================================================================
# heavy_hitters.cr - Space-Saving heavy hitters and burstiness detection
# =============================================================================
#
# Implements the Space-Saving stream sketch algorithm (Metwally et al. 2005)
# to identify dominant "elephant flows" and heavy talkers in constant memory,
# along with peak-to-average burstiness ratio metrics.
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "../dissect/decoded_packet"

module Filament
  module Stats
    # A single heavy hitter tracked in the Space-Saving sketch
    class HeavyHitterItem
      getter key : String
      property count : UInt64
      property error : UInt64

      def initialize(@key : String, @count : UInt64 = 0_u64, @error : UInt64 = 0_u64)
      end
    end

    # Space-Saving stream sketch finding top-K frequent elements in streaming traffic
    class SpaceSavingSketch
      getter k : Int32
      getter items : Hash(String, HeavyHitterItem)
      getter total_volume : UInt64

      def initialize(@k : Int32 = 100)
        @items = Hash(String, HeavyHitterItem).new
        @total_volume = 0_u64
      end

      # Updates sketch with observed item and weight (bytes or packet count)
      def update(key : String, weight : UInt64 = 1_u64) : Nil
        @total_volume += weight

        if item = @items[key]?
          item.count += weight
        elsif @items.size < @k
          @items[key] = HeavyHitterItem.new(key, weight, 0_u64)
        else
          # Find element with minimum count
          min_key, min_item = @items.min_by { |_k, v| v.count }
          @items.delete(min_key)

          # Replace with new item, inheriting minimum count as error bound
          @items[key] = HeavyHitterItem.new(key, min_item.count + weight, min_item.count)
        end
      end

      # Returns top N frequent items sorted by frequency count
      def top(n : Int32 = 10) : Array(HeavyHitterItem)
        @items.values.sort_by { |item| -item.count.to_i64 }.first(n)
      end

      # Checks if an item represents a true heavy hitter (exceeds threshold phi of total traffic)
      def heavy_hitter?(key : String, phi : Float64 = 0.05) : Bool
        item = @items[key]?
        return false unless item
        threshold = (@total_volume.to_f64 * phi).to_u64
        item.count >= threshold
      end
    end

    # Diagnoses burstiness and traffic concentration
    class TrafficBurstinessAnalyzer
      getter peak_to_average_ratio : Float64
      getter elephant_flows_pct : Float64

      def initialize(@peak_to_average_ratio : Float64 = 1.0, @elephant_flows_pct : Float64 = 0.0)
      end

      # Calculates peak-to-average throughput ratio
      def self.calculate_par(peak_rate : Float64, avg_rate : Float64) : Float64
        avg_rate > 0.0 ? (peak_rate / avg_rate) : 1.0
      end
    end
  end
end
